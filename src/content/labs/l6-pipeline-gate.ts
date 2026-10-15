import type { LabDef } from '../../engine/lab';
import type { PipelineRun } from '../../engine/types';
import { failedTools, ranTool } from '../../engine/pipeline';
import { baseFiles, CART_TESTS, DOCKERFILE_OK, DOCKERIGNORE_OK, npmFiles, ORDER_TESTS, ORDERS_SAFE, SERVER_TEST, TEAM } from '../shopflow';
import { headFiles, isPushed, runForHead } from './common';

const FAKE_REPORT_KEY = 'AKIAFAKETRAININGKEY3';

const REPORT_CONFIG = `// Nightly sales export to the analytics bucket
module.exports = {
  bucket: 'shopflow-analytics',
  accessKeyId: '${FAKE_REPORT_KEY}',
};
`;

const ORDERS_ONE_FLAW = ORDERS_SAFE.replace(
  `  const rows = await db.query(
    'SELECT id, total, status FROM orders WHERE customer_id = $1',
    [req.query.customer],
  );`,
  `  const rows = await db.query("SELECT id, total, status FROM orders WHERE customer_id = '" + req.query.customer + "'");`,
);

export const CI_UNGATED = `name: ci
on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npm ci
      - run: npm test

  deploy:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker build -t registry.shopflow.local/shopflow-api:\${{ github.sha }} .
      - run: docker push registry.shopflow.local/shopflow-api:\${{ github.sha }}
      - run: kubectl set image deployment/shopflow-api api=registry.shopflow.local/shopflow-api:\${{ github.sha }}
`;

const SECURITY_TOOLS = ['gitleaks', 'semgrep', 'trivy fs', 'npm audit'];
const deployJob = (r: PipelineRun) => r.jobs.find((j) => j.steps.some((st) => st.log.some((l) => /kubectl/.test(l))) || /deploy/i.test(j.id));

function bypasses(wf: string): string[] {
  const out: string[] = [];
  if (/\|\|\s*true/.test(wf)) out.push('"|| true" hides a failing command');
  if (/continue-on-error:\s*true/.test(wf)) out.push('continue-on-error: true');
  if (/--soft-fail|soft_fail:\s*true/.test(wf)) out.push('soft-fail');
  if (/--exit-code[ =]0|exit-code:\s*['"]?0/.test(wf)) out.push('exit-code 0');
  if (/semgrep\s+scan/.test(wf) && !/semgrep\s+scan[^\n]*--error/.test(wf)) out.push('semgrep scan without --error never fails');
  if (/trivy\s+fs/.test(wf) && !/trivy\s+fs[^\n]*--exit-code[ =]1/.test(wf)) out.push('trivy fs without --exit-code 1 never fails');
  return out;
}

const workflow = (files: Record<string, string>) => files['.github/workflows/ci.yml'] ?? '';

export const pipelineLab: LabDef = {
  id: 'pipeline-gate',
  level: 3,
  title: 'Build the security gate',
  track: 'CI/CD security',
  minutes: 45,
  summary: 'Add blocking secrets, SAST and SCA stages to a GitHub Actions pipeline, prove the gate stops a vulnerable deploy, then remediate until it ships green.',
  story:
    'An audit found that shopflow-api deploys to staging on every push with no security checks — and the pipeline is green. Green does not mean safe. Wire in real gates before deploy, show that they block, then fix what they catch.',
  ticket: 'AUD-212 — Add blocking secret, SAST and dependency gates before deploy. Demonstrate a blocked deploy, remove any bypasses, then ship a green, gated build to staging.',
  skills: ['Pipeline design', 'Quality gates', 'Exit codes', 'Remediation under a gate'],
  tools: ['GitHub Actions YAML', 'gitleaks', 'semgrep', 'trivy', 'kubectl'],
  concepts: [
    { term: 'Gates work by exit code', text: 'A step fails only if its command exits non-zero. Many scanners exit 0 by default — semgrep needs --error, trivy needs --exit-code 1.' },
    { term: 'needs:', text: 'Make deploy depend on the security job (needs: [security]). If the gate fails, deploy is skipped.' },
    { term: 'Bypasses', text: '"|| true", continue-on-error and --soft-fail silently turn a gate into a report nobody reads.' },
  ],
  openFile: '.github/workflows/ci.yml',
  seed: () => {
    const files = baseFiles({
      ...npmFiles({ express: '^4.21.2', pg: '^8.13.1', lodash: '4.17.15' }, { express: '4.21.2', pg: '8.13.1', lodash: '4.17.15', jest: '29.7.0' }),
      'src/routes/orders.js': ORDERS_ONE_FLAW,
      'src/config/reporting.js': REPORT_CONFIG,
      Dockerfile: DOCKERFILE_OK,
      '.dockerignore': DOCKERIGNORE_OK,
      '.github/workflows/ci.yml': CI_UNGATED,
    });
    const initial = { ...files };
    delete initial['src/config/reporting.js'];
    return {
      history: [
        { message: 'Initial ShopFlow API', author: TEAM.priya, daysAgo: 50, files: initial },
        { message: 'Add nightly sales export', author: TEAM.marco, daysAgo: 9, files },
      ],
      iamKeys: [{ id: FAKE_REPORT_KEY, user: 'svc-reporting', status: 'Active', created: '2026-10-06T10:00:00Z' }],
      flags: { leakedKeyId: FAKE_REPORT_KEY },
      registryFromHead: 'registry.shopflow.local/shopflow-api:1.3.9',
      stagingFromHead: true,
      runInitialPipeline: true,
    };
  },
  tests: [...ORDER_TESTS, SERVER_TEST, ...CART_TESTS],
  objectives: [
    {
      id: 'secrets-stage',
      title: 'Pipeline runs a secrets scan',
      guide: 'Add a `security` job with a Gitleaks step (`run: gitleaks git -v --redact`), commit, push and watch it run.',
      hints: ['Put the new job before deploy and make deploy `needs: [build, security]`.'],
      check: (s) => s.pipelineRuns.some((r) => ranTool(r, 'gitleaks')),
    },
    {
      id: 'sast-stage',
      title: 'Pipeline runs SAST that can fail the build',
      guide: 'Add `semgrep scan --config auto --error` (or `semgrep ci`).',
      hints: ['Without --error semgrep reports but exits 0.'],
      check: (s) => s.pipelineRuns.some((r) => ranTool(r, 'semgrep')),
    },
    {
      id: 'sca-stage',
      title: 'Pipeline runs a dependency scan that can fail the build',
      guide: 'Add `trivy fs --severity HIGH,CRITICAL --exit-code 1 .` (or `npm audit --audit-level=high`).',
      hints: ['Trivy reads package-lock.json from the checkout.'],
      check: (s) => s.pipelineRuns.some((r) => ranTool(r, 'trivy fs') || ranTool(r, 'npm audit')),
    },
    {
      id: 'blocked',
      title: 'Prove it: a run where the gate failed and deploy was skipped',
      guide: 'Push your gated workflow **before** fixing the code. The security job should fail and the deploy job must show as skipped.',
      hints: ['If deploy still ran, it does not depend on the security job (needs:).'],
      check: (s) => s.pipelineRuns.some((r) => failedTools(r).some((t) => SECURITY_TOOLS.some((x) => t.startsWith(x))) && deployJob(r)?.status === 'skipped'),
    },
    {
      id: 'no-bypass',
      title: 'No bypasses in the committed workflow',
      guide: 'No `|| true`, no `continue-on-error: true`, no soft-fail, and every scanner configured to exit non-zero on findings.',
      hints: ['The checker lists what it found in the workflow on the latest commit.'],
      check: (s) => {
        const wf = workflow(headFiles(s));
        return /gitleaks/.test(wf) && /semgrep/.test(wf) && /(trivy fs|npm audit)/.test(wf) && bypasses(wf).length === 0;
      },
    },
    {
      id: 'contain',
      title: 'Deactivate the reporting key the gate found',
      guide: 'The secrets scan found an access key for `svc-reporting`. Deactivate it in IAM, then remove it from code (read it from the environment).',
      command: `aws iam update-access-key --user-name svc-reporting --access-key-id ${FAKE_REPORT_KEY} --status Inactive`,
      hints: ['History still contains the key: rewrite history (lab 1) or — after rotation — add the finding fingerprint to .gitleaksignore with a comment.'],
      check: (s) => !s.iamKeys.some((k) => k.id === FAKE_REPORT_KEY && k.status === 'Active'),
    },
    {
      id: 'green',
      title: 'Ship it: gated pipeline green and staging runs your commit',
      guide: 'Fix the SQL injection, upgrade lodash, remove the hard-coded key, push — every gate must pass and deploy must update staging.',
      hints: ['Run the same scanners locally first to iterate faster.', 'npm install lodash@4.17.21 updates package.json and the lockfile.'],
      check: (s) => {
        const r = runForHead(s);
        return !!r && r.status === 'passed' && isPushed(s) && SECURITY_TOOLS.filter((t) => ranTool(r, t)).length >= 3 && failedTools(r).length === 0 && s.staging?.commit === s.head;
      },
    },
  ],
};

export { bypasses };
