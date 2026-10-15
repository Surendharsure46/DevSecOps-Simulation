import type { Files, LabState, PipelineJob, PipelineRun, PipelineStep } from './types';
import { parseYaml, YamlError } from './yaml';
import { runLine, type ShellCtx, type TestCase } from './shell';
import { C, hash53 } from './util';

// GitHub-Actions-compatible pipeline runner. Jobs, needs, steps (run/uses/with/env/if,
// continue-on-error) execute against the pushed commit using the same tool engine as the
// learner's terminal, so gates behave exactly like the tools' exit codes.

type Obj = Record<string, unknown>;

interface StepDef {
  name?: string;
  uses?: string;
  run?: string;
  with?: Obj;
  env?: Obj;
  if?: string;
  'continue-on-error'?: boolean;
}

interface JobDef {
  name?: string;
  needs?: string | string[];
  steps?: StepDef[];
  env?: Obj;
  if?: string;
}

const KNOWN_SECRETS = new Set(['GITHUB_TOKEN', 'REGISTRY_PASSWORD', 'KUBE_CONFIG', 'SEMGREP_APP_TOKEN']);

function interpolate(s: string, commit: string): string {
  return s.replace(/\$\{\{\s*([^}]+?)\s*\}\}/g, (_, expr: string) => {
    if (expr === 'github.sha') return commit;
    if (expr === 'github.ref_name') return 'main';
    if (expr === 'github.repository') return 'shopflow/shopflow-api';
    const sec = /^secrets\.(\w+)$/.exec(expr);
    if (sec) return KNOWN_SECRETS.has(sec[1]) ? '***' : '';
    return '';
  });
}

const needsOf = (j: JobDef): string[] => (!j.needs ? [] : Array.isArray(j.needs) ? j.needs.map(String) : [String(j.needs)]);

export function findWorkflow(files: Files): string | null {
  return Object.keys(files).filter((p) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(p)).sort()[0] ?? null;
}

export interface WorkflowCheck {
  ok: boolean;
  error?: string;
  jobs?: Record<string, JobDef>;
  order?: string[];
}

export function validateWorkflow(path: string, src: string): WorkflowCheck {
  let doc: unknown;
  try {
    doc = parseYaml(src);
  } catch (e) {
    const line = e instanceof YamlError ? e.line : 1;
    return { ok: false, error: `Invalid workflow file: ${path}#L${line}\nYou have an error in your yaml syntax on line ${line}: ${(e as Error).message}` };
  }
  if (!doc || typeof doc !== 'object') return { ok: false, error: `Invalid workflow file: ${path}#L1\nNo jobs were defined` };
  const d = doc as Obj;
  const on = d.on;
  const triggers = typeof on === 'string' ? [on] : Array.isArray(on) ? on : on && typeof on === 'object' ? Object.keys(on as Obj) : [];
  if (!triggers.includes('push')) return { ok: false, error: `${path}: the workflow is not triggered on push (add "on: push")` };
  const jobs = d.jobs as Record<string, JobDef> | undefined;
  if (!jobs || typeof jobs !== 'object' || !Object.keys(jobs).length) return { ok: false, error: `Invalid workflow file: ${path}\nNo jobs were defined` };
  for (const [id, j] of Object.entries(jobs)) {
    if (!j || typeof j !== 'object') return { ok: false, error: `Invalid workflow file: ${path}\nThe job '${id}' is not a mapping` };
    if (!Array.isArray(j.steps) || !j.steps.length) return { ok: false, error: `Invalid workflow file: ${path}\nJob '${id}': "steps" is required` };
    for (const n of needsOf(j)) if (!(n in jobs)) return { ok: false, error: `Invalid workflow file: ${path}\nJob '${id}' depends on unknown job '${n}'.` };
    for (const st of j.steps) if (!st || typeof st !== 'object' || (!st.run && !st.uses)) return { ok: false, error: `Invalid workflow file: ${path}\nJob '${id}': every step must define "uses" or "run"` };
  }
  const order: string[] = [];
  const state: Record<string, number> = {};
  const visit = (id: string): string | null => {
    if (state[id] === 2) return null;
    if (state[id] === 1) return id;
    state[id] = 1;
    for (const n of needsOf(jobs[id])) {
      const c = visit(n);
      if (c) return c;
    }
    state[id] = 2;
    order.push(id);
    return null;
  };
  for (const id of Object.keys(jobs)) {
    const cyc = visit(id);
    if (cyc) return { ok: false, error: `Invalid workflow file: ${path}\nJob '${cyc}' has a circular dependency (needs).` };
  }
  return { ok: true, jobs, order };
}

function actionToCommands(uses: string, w: Obj): { cmds: string[]; note?: string; softFail?: boolean; error?: string } {
  const name = uses.split('@')[0].toLowerCase();
  const g = (k: string, d = '') => (w[k] === undefined || w[k] === null ? d : String(w[k]));
  switch (name) {
    case 'actions/checkout':
      return { cmds: ['__checkout'] };
    case 'actions/setup-node':
      return { cmds: [], note: `Successfully set up Node.js ${g('node-version', '20')}.x` };
    case 'actions/cache':
    case 'actions/upload-artifact':
    case 'docker/setup-buildx-action':
    case 'docker/login-action':
    case 'azure/setup-kubectl':
      return { cmds: [], note: `${name}: done` };
    case 'gitleaks/gitleaks-action':
      return { cmds: ['gitleaks git -v --redact --exit-code 1'] };
    case 'semgrep/semgrep-action':
    case 'returntocorp/semgrep-action':
      return { cmds: [`semgrep ci --config ${g('config', 'auto')}`] };
    case 'aquasecurity/trivy-action': {
      const type = g('scan-type', 'image');
      const flags = [g('severity') && `--severity ${g('severity')}`, `--exit-code ${g('exit-code', '0')}`, g('ignore-unfixed') === 'true' && '--ignore-unfixed'].filter(Boolean).join(' ');
      if (type === 'fs' || type === 'repo') return { cmds: [`trivy fs ${flags} ${g('scan-ref', '.')}`] };
      if (type === 'config') return { cmds: [`trivy config ${flags} ${g('scan-ref', '.')}`] };
      return g('image-ref') ? { cmds: [`trivy image ${flags} ${g('image-ref')}`] } : { cmds: [], error: 'Input required and not supplied: image-ref' };
    }
    case 'bridgecrewio/checkov-action':
      return { cmds: [`checkov -d ${g('directory', '.')} --compact${g('soft_fail') === 'true' ? ' --soft-fail' : ''}`] };
    case 'hadolint/hadolint-action':
      return { cmds: [`hadolint --failure-threshold ${g('failure-threshold', 'info')} ${g('dockerfile', 'Dockerfile')}`] };
    case 'anchore/sbom-action':
      return { cmds: [`syft . -o cyclonedx-json=${g('output-file', 'sbom.cdx.json')}`] };
    case 'docker/build-push-action': {
      const tag = g('tags').split(/[,\n]/).map((t) => t.trim()).filter(Boolean)[0];
      if (!tag) return { cmds: [], error: 'Input required: tags' };
      return { cmds: [`docker build -t ${tag} .`, ...(g('push') === 'true' ? [`docker push ${tag}`] : [])] };
    }
    case 'zaproxy/action-baseline':
    case 'zaproxy/action-full-scan': {
      const tool = name.endsWith('baseline') ? 'zap-baseline.py' : 'zap-full-scan.py';
      const rules = g('rules_file_name');
      return { cmds: [`${tool} -t ${g('target')}${rules ? ` -c ${rules}` : ''} ${g('cmd_options')}`.trim()], softFail: g('fail_action', 'false') !== 'true' };
    }
    default:
      return { cmds: [], error: `Unable to resolve action \`${uses}\`, repository or version not found` };
  }
}

const TOOL_WORDS = ['gitleaks', 'semgrep', 'trivy', 'checkov', 'hadolint', 'syft', 'npm', 'docker', 'kubectl', 'zap-baseline.py', 'zap-full-scan.py', 'terraform', 'kyverno'];

function track(run: PipelineRun, line: string, code: number) {
  const w = line.trim().split(/\s+/);
  const tool = ['npm', 'docker', 'trivy', 'terraform', 'kubectl'].includes(w[0]) ? `${w[0]} ${w[1] ?? ''}`.trim() : w[0];
  if (!TOOL_WORDS.some((t) => tool.startsWith(t))) return;
  const soft = /\|\|\s*true\s*$/.test(line);
  run.toolExits[tool] = soft ? 0 : code;
}

export function runPipeline(s: LabState, commitId: string, tests: TestCase[]): PipelineRun | null {
  const commit = s.commits.find((c) => c.id === commitId);
  if (!commit) return null;
  const wfPath = findWorkflow(commit.files);
  if (!wfPath) return null;
  const run: PipelineRun = { id: s.pipelineRuns.length + 1, commit: commitId, message: commit.message, status: 'invalid', jobs: [], at: Date.now(), toolExits: {} };
  const check = validateWorkflow(wfPath, commit.files[wfPath]);
  if (!check.ok) return { ...run, error: check.error };
  const results: Record<string, PipelineJob> = {};
  for (const jid of check.order!) {
    const j = check.jobs![jid];
    const job: PipelineJob = { id: jid, name: j.name ?? jid, needs: needsOf(j), status: 'pending', steps: [] };
    results[jid] = job;
    if (job.needs.some((n) => results[n]?.status === 'failed' || results[n]?.status === 'skipped') && !/always\(\)/.test(j.if ?? '')) {
      job.status = 'skipped';
      job.steps = (j.steps ?? []).map((st) => ({ name: stepName(st), status: 'skipped', log: [], ms: 0 }));
      continue;
    }
    const fs: Files = {};
    const ctx: ShellCtx = { s, fs, installed: {}, pipeline: true, env: { CI: 'true', GITHUB_SHA: commitId, ...strEnv(j.env, commitId) }, flags: {}, tests, commit: commitId };
    let failed = false;
    job.steps.push({ name: 'Set up job', status: 'passed', log: ['Runner image: ubuntu-24.04', `Job: ${job.name}`], ms: 900 });
    for (const st of j.steps ?? []) {
      const step: PipelineStep = { name: stepName(st), status: 'pending', log: [], ms: 0 };
      job.steps.push(step);
      const cond = st.if ?? '';
      if (failed ? !/always\(\)|failure\(\)/.test(cond) : /failure\(\)/.test(cond)) {
        step.status = 'skipped';
        continue;
      }
      const stepEnv = strEnv(st.env, commitId);
      const saved = { ...ctx.env };
      Object.assign(ctx.env, stepEnv);
      let code = 0;
      const exec = (cmd: string) => {
        step.log.push(C.cyan(`$ ${cmd}`));
        const r = runLine(cmd, ctx);
        step.log.push(...r.out.filter((l) => l !== '\x1bc'));
        track(run, cmd, r.code);
        return r.code;
      };
      if (st.uses) {
        const a = actionToCommands(interpolate(st.uses, commitId), Object.fromEntries(Object.entries(st.with ?? {}).map(([k, v]) => [k, typeof v === 'string' ? interpolate(v, commitId) : v])));
        step.log.push(C.gray(`Run ${st.uses}`));
        if (a.error) {
          step.log.push(C.red(`Error: ${a.error}`));
          code = 1;
        }
        if (a.note) step.log.push(a.note);
        for (const cmd of a.cmds) {
          if (cmd === '__checkout') {
            Object.assign(fs, commit.files);
            step.log.push('Syncing repository: shopflow/shopflow-api', `HEAD is now at ${commitId.slice(0, 7)} ${commit.message}`);
            continue;
          }
          code = exec(cmd);
          if (code) break;
        }
        if (a.softFail && code) {
          step.log.push(C.yellow('Alerts were found but fail_action is false → this step does not fail the build.'));
          code = 0;
        }
      } else if (st.run) {
        const lines = interpolate(st.run, commitId).replace(/\\\n\s*/g, ' ').split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
        for (const line of lines) {
          if (!Object.keys(fs).length && !/^(echo|export|sleep|zap-|curl)/.test(line)) step.log.push(C.yellow('warning: the workspace is empty — did you forget actions/checkout?'));
          code = exec(line);
          if (code) break;
        }
      }
      ctx.env = saved;
      step.ms = 400 + (hash53(step.name + commitId) % 9000);
      if (code) {
        step.log.push(C.red(`Error: Process completed with exit code ${code}.`));
        if (st['continue-on-error'] === true) {
          step.status = 'warning';
          step.log.push(C.yellow('continue-on-error is enabled — the job continues despite this failure.'));
        } else {
          step.status = 'failed';
          failed = true;
        }
      } else step.status = 'passed';
    }
    job.steps.push({ name: 'Complete job', status: 'passed', log: ['Cleaning up orphan processes'], ms: 200 });
    job.status = failed ? 'failed' : 'passed';
  }
  run.jobs = check.order!.map((id) => results[id]);
  run.status = run.jobs.some((j) => j.status === 'failed') ? 'failed' : 'passed';
  return run;
}

function stepName(st: StepDef): string {
  if (st.name) return String(st.name);
  if (st.uses) return `Run ${st.uses}`;
  return `Run ${String(st.run ?? '').split('\n')[0].slice(0, 60)}`;
}

function strEnv(env: Obj | undefined, commit: string): Record<string, string> {
  return Object.fromEntries(Object.entries(env ?? {}).map(([k, v]) => [k, interpolate(String(v ?? ''), commit)]));
}

export const ranTool = (run: PipelineRun, prefix: string) => Object.keys(run.toolExits).some((k) => k.startsWith(prefix));
export const failedTools = (run: PipelineRun) => Object.entries(run.toolExits).filter(([, v]) => v !== 0).map(([k]) => k);
