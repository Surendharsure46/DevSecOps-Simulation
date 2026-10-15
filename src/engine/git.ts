import type { Commit, Files, LabState } from './types';
import { hexDigest } from './util';

// In-memory Git: working tree, index, commits, one remote with push / force-push,
// .gitignore handling and git-filter-repo style history rewriting.

export const AUTHOR = 'You <you@shopflow.dev>';

export function makeCommit(files: Files, parent: string | null, message: string, author = AUTHOR, date = new Date().toISOString()): Commit {
  return { id: hexDigest(JSON.stringify(files) + (parent ?? '') + message + author + date), parent, message, author, date, files: { ...files } };
}

export function headCommit(s: LabState): Commit | undefined {
  return s.commits.find((c) => c.id === s.head);
}

export function ignoredBy(files: Files): (p: string) => boolean {
  const pats = (files['.gitignore'] ?? '')
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
  return (p: string) =>
    pats.some((pat) => {
      const clean = pat.replace(/^\//, '').replace(/\/$/, '');
      if (clean.includes('*')) return new RegExp('(^|/)' + clean.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*') + '(/.*)?$').test(p);
      return p === clean || p.startsWith(clean + '/') || p.endsWith('/' + clean);
    });
}

export interface StatusEntry {
  path: string;
  staged: 'A' | 'M' | 'D' | null;
  unstaged: 'M' | 'D' | null;
  untracked: boolean;
}

export function status(s: LabState): StatusEntry[] {
  const head = headCommit(s)?.files ?? {};
  const ign = ignoredBy(s.files);
  const out: StatusEntry[] = [];
  for (const p of [...new Set([...Object.keys(head), ...Object.keys(s.index), ...Object.keys(s.files)])].sort()) {
    const inHead = p in head;
    const inIdx = p in s.index;
    const inWt = p in s.files;
    let staged: StatusEntry['staged'] = null;
    if (inIdx && !inHead) staged = 'A';
    else if (!inIdx && inHead) staged = 'D';
    else if (inIdx && inHead && s.index[p] !== head[p]) staged = 'M';
    let unstaged: StatusEntry['unstaged'] = null;
    let untracked = false;
    if (inIdx && !inWt) unstaged = 'D';
    else if (inIdx && inWt && s.index[p] !== s.files[p]) unstaged = 'M';
    else if (!inIdx && inWt) {
      if (ign(p)) continue;
      untracked = true;
    }
    if (staged || unstaged || untracked) out.push({ path: p, staged, unstaged, untracked });
  }
  return out;
}

export function addPaths(s: LabState, paths: string[]): string[] {
  const errors: string[] = [];
  const ign = ignoredBy(s.files);
  const force = paths.includes('-f');
  const known = [...new Set([...Object.keys(s.files), ...Object.keys(s.index)])];
  const all = paths.includes('.') || paths.includes('-A') || paths.includes('--all');
  const targets = all ? known : [];
  if (!all)
    for (const p of paths.filter((x) => !x.startsWith('-'))) {
      const clean = p.replace(/^\.\//, '').replace(/\/$/, '');
      const hits = known.filter((f) => f === clean || f.startsWith(clean + '/'));
      if (!hits.length) errors.push(`fatal: pathspec '${p}' did not match any files`);
      else if (!force && hits.every((h) => ign(h) && !(h in s.index))) errors.push(`The following paths are ignored by one of your .gitignore files:\n${p}\nhint: Use -f if you really want to add them.`);
      targets.push(...hits);
    }
  for (const t of targets) {
    if (t in s.files) {
      if (ign(t) && !(t in s.index) && !force) continue;
      s.index[t] = s.files[t];
    } else delete s.index[t];
  }
  return errors;
}

export function commitIndex(s: LabState, message: string): Commit | null {
  const head = headCommit(s);
  if (head && JSON.stringify(head.files) === JSON.stringify(s.index)) return null;
  const c = makeCommit(s.index, s.head || null, message);
  s.commits.unshift(c);
  s.head = c.id;
  return c;
}

/** Ancestors of `id` (inclusive), newest first. */
export function ancestry(commits: Commit[], id: string | null): Commit[] {
  const out: Commit[] = [];
  let cur = commits.find((c) => c.id === id);
  while (cur) {
    out.push(cur);
    const parent: string | null = cur.parent;
    cur = parent ? commits.find((c) => c.id === parent) : undefined;
  }
  return out;
}

export function isAncestor(commits: Commit[], anc: string, of: string): boolean {
  return ancestry(commits, of).some((c) => c.id === anc);
}

function rewrite(s: LabState, map: (files: Files) => Files): number {
  const chain = ancestry(s.commits, s.head).reverse();
  let parent: string | null = null;
  let rewritten = 0;
  const next: Commit[] = [];
  for (const c of chain) {
    const files = map(c.files);
    if (JSON.stringify(files) !== JSON.stringify(c.files)) rewritten++;
    const nc = makeCommit(files, parent, c.message, c.author, c.date);
    next.unshift(nc);
    parent = nc.id;
  }
  const oldHead = headCommit(s)?.files ?? {};
  s.commits = next;
  s.head = parent ?? '';
  const head = headCommit(s);
  if (head) {
    s.index = { ...head.files };
    for (const p of Object.keys(oldHead)) delete s.files[p];
    Object.assign(s.files, head.files);
  }
  return rewritten;
}

export function filterRepoReplace(s: LabState, rules: { from: string | RegExp; to: string }[]): number {
  return rewrite(s, (files) => {
    const out: Files = {};
    for (const [p, t] of Object.entries(files)) {
      let nt = t;
      for (const r of rules) nt = typeof r.from === 'string' ? nt.split(r.from).join(r.to) : nt.replace(r.from, r.to);
      out[p] = nt;
    }
    return out;
  });
}

export function filterRepoInvertPaths(s: LabState, paths: string[]): number {
  return rewrite(s, (files) => Object.fromEntries(Object.entries(files).filter(([p]) => !paths.some((x) => p === x || p.startsWith(x.replace(/\/$/, '') + '/')))));
}
