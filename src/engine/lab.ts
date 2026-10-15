import type { Commit, Files, IamKey, LabState, ToolName } from './types';
import { makeCommit } from './git';
import { readLock } from './sca';
import { REPO_URL, revOf, type TestCase } from './shell';
import { runPipeline } from './pipeline';
import { dockerBuild } from './container';

export type Mode = 'guided' | 'standard' | 'expert';

export interface Objective {
  id: string;
  title: string;
  /** guided-mode explanation (supports `code` and **bold**) */
  guide: string;
  /** progressive hints */
  hints: string[];
  /** example command offered in guided mode */
  command?: string;
  bonus?: boolean;
  check: (s: LabState) => boolean;
}

export interface SeedCommit {
  message: string;
  author: string;
  daysAgo: number;
  files: Files;
}

export interface LabSeed {
  history: SeedCommit[];
  /** untracked / ignored files present only in the working tree */
  local?: Files;
  iamKeys?: IamKey[];
  flags?: Record<string, string | number | boolean>;
  /** build HEAD and publish it to the registry under this tag */
  registryFromHead?: string;
  stagingFromHead?: boolean;
  runInitialPipeline?: boolean;
}

export interface LabDef {
  id: string;
  level: number;
  title: string;
  track: string;
  minutes: number;
  summary: string;
  story: string;
  ticket: string;
  skills: string[];
  tools: string[];
  concepts: { term: string; text: string }[];
  openFile: string;
  seed: () => LabSeed;
  tests: TestCase[];
  objectives: Objective[];
}

export function createLabState(def: LabDef): LabState {
  const seed = def.seed();
  const commits: Commit[] = [];
  let parent: string | null = null;
  for (const h of seed.history) {
    const c = makeCommit(h.files, parent, h.message, h.author, new Date(Date.now() - h.daysAgo * 86400000).toISOString());
    commits.unshift(c);
    parent = c.id;
  }
  const head = commits[0];
  const s: LabState = {
    labId: def.id,
    files: { ...head.files, ...(seed.local ?? {}) },
    index: { ...head.files },
    commits,
    head: head.id,
    remote: { url: REPO_URL, head: head.id, commits: [...commits] },
    installed: readLock(head.files) ?? {},
    iamKeys: seed.iamKeys ?? [],
    images: {},
    registry: {},
    container: null,
    staging: null,
    scans: {},
    pipelineRuns: [],
    flags: { ...(seed.flags ?? {}) },
    activity: [{ t: Date.now(), kind: 'system', text: `Lab started: ${def.title}` }],
    hintsUsed: [],
    startedAt: Date.now(),
    completedAt: null,
    achieved: [],
  };
  let stagingImage = 'registry.shopflow.local/shopflow-api:1.3.9';
  if (seed.registryFromHead) {
    const b = dockerBuild(head.files, seed.registryFromHead);
    if (b.image) s.registry[seed.registryFromHead] = b.image;
    stagingImage = seed.registryFromHead;
  }
  if (seed.stagingFromHead) s.staging = { image: stagingImage, commit: head.id, files: head.files, installed: s.installed, at: Date.now() - 3600000 };
  if (seed.runInitialPipeline) {
    const run = runPipeline(s, head.id, def.tests);
    if (run) s.pipelineRuns.push(run);
  }
  return s;
}

/**
 * Run after every learner action: trigger CI for a fresh push and record newly
 * achieved objectives. Returns the ids of objectives completed by this action.
 */
export function settle(def: LabDef, s: LabState): { newlyAchieved: string[]; run: ReturnType<typeof runPipeline> } {
  let run: ReturnType<typeof runPipeline> = null;
  const pushed = s.flags.pushRequested;
  if (typeof pushed === 'string' && pushed) {
    delete s.flags.pushRequested;
    run = runPipeline(s, pushed, def.tests);
    if (run) {
      s.pipelineRuns.push(run);
      s.activity.push({ t: Date.now(), kind: 'pipeline', text: `Pipeline #${run.id} ${run.status} for ${pushed.slice(0, 7)}` });
    }
  }
  const newlyAchieved: string[] = [];
  for (const o of def.objectives) {
    if (s.achieved.includes(o.id)) continue;
    let ok = false;
    try {
      ok = o.check(s);
    } catch {
      ok = false;
    }
    if (ok) {
      s.achieved.push(o.id);
      newlyAchieved.push(o.id);
      s.activity.push({ t: Date.now(), kind: 'objective', text: `✔ ${o.title}` });
    }
  }
  if (!s.completedAt && def.objectives.filter((o) => !o.bonus).every((o) => s.achieved.includes(o.id))) s.completedAt = Date.now();
  return { newlyAchieved, run };
}

export function failingTests(def: LabDef, files: Files, installed: Record<string, string>): string[] {
  return def.tests.filter((t) => t.run(files, installed) !== null).map((t) => t.name);
}

/** `npm test` was run on exactly the current code and passed. */
export function testsGreenNow(def: LabDef, s: LabState): boolean {
  return s.flags.testsRev === revOf(s) && s.flags.testsPassed === true && failingTests(def, s.files, s.installed).length === 0;
}

export function scanFresh(s: LabState, tool: ToolName): boolean {
  return s.scans[tool]?.rev === revOf(s);
}

export function score(def: LabDef, s: LabState, mode: Mode): { score: number; max: number } {
  const req = def.objectives.filter((o) => !o.bonus);
  const done = req.filter((o) => s.achieved.includes(o.id)).length;
  const bonus = def.objectives.filter((o) => o.bonus && s.achieved.includes(o.id)).length;
  let pts = Math.round((done / Math.max(1, req.length)) * 100) + bonus * 10;
  if (mode === 'standard') pts -= s.hintsUsed.length * 5;
  const mins = ((s.completedAt ?? Date.now()) - s.startedAt) / 60000;
  if (mode === 'expert' && s.completedAt && mins <= def.minutes) pts += 20;
  return { score: Math.max(0, pts), max: 100 + def.objectives.filter((o) => o.bonus).length * 10 + (mode === 'expert' ? 20 : 0) };
}
