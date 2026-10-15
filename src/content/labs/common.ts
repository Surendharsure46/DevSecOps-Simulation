import type { Files, LabState } from '../../engine/types';
import { headCommit } from '../../engine/git';
import { lookupBase, parseDockerfile } from '../../engine/container';
import { requires } from '../../engine/appmodel';
import type { TestCase } from '../../engine/shell';

// Helpers shared by lab objective checks.

export const headFiles = (s: LabState): Files => headCommit(s)?.files ?? {};
export const isPushed = (s: LabState) => !!s.remote.url && s.remote.head === s.head;
export const runForHead = (s: LabState) => [...s.pipelineRuns].reverse().find((r) => r.commit === s.head);

export interface FinalStage {
  from: string;
  user: string | null;
  healthcheck: boolean;
  secretEnv: string[];
}

export function finalStage(src: string | undefined): FinalStage | null {
  if (!src) return null;
  const { instrs, error } = parseDockerfile(src);
  if (error) return null;
  const st: FinalStage = { from: '', user: null, healthcheck: false, secretEnv: [] };
  for (const i of instrs) {
    if (i.cmd === 'FROM') {
      st.from = i.args.split(/\s+/).filter((x) => !x.startsWith('--'))[0];
      st.user = st.from.endsWith(':nonroot') ? 'nonroot' : null;
      st.healthcheck = false;
    }
    if (i.cmd === 'USER') st.user = i.args.split(':')[0];
    if (i.cmd === 'HEALTHCHECK') st.healthcheck = true;
    if ((i.cmd === 'ENV' || i.cmd === 'ARG') && /(PASSWORD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY)\w*\s*[= ]\s*\S+/i.test(i.args)) st.secretEnv.push(i.args.split(/[= ]/)[0]);
  }
  return st;
}

export function runsAsNonRoot(src: string | undefined): boolean {
  const f = finalStage(src);
  return !!f?.user && f.user !== 'root' && f.user !== '0';
}

export function hasMinimalPinnedBase(src: string | undefined): boolean {
  const f = finalStage(src);
  if (!f) return false;
  const b = lookupBase(f.from);
  return !!b && b.family !== 'debian' && f.from.includes(':') && !f.from.endsWith(':latest');
}

export function dockerignoreHas(files: Files, ...entries: string[]): boolean {
  const lines = (files['.dockerignore'] ?? '').split('\n').map((l) => l.trim().replace(/^\.?\//, '').replace(/\/$/, ''));
  return entries.every((e) => lines.includes(e) || lines.includes('**/' + e));
}

export const requiredModulesInstalled: TestCase = {
  suite: 'tests/server.test.js',
  name: 'every module required in src/ is installed',
  run: (fs, installed) => {
    for (const [p, t] of Object.entries(fs)) {
      if (!p.startsWith('src/') || !p.endsWith('.js')) continue;
      for (const r of requires(t)) if (!['fs', 'path', 'crypto', 'http', 'https'].includes(r) && !installed[r]) return `Cannot find module '${r}' from '${p}'`;
    }
    return null;
  },
};
