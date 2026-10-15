// Small, dependency-free helpers shared by the lab engine.

/** cyrb53: fast deterministic 53-bit string hash. */
export function hash53(str: string, seed = 0): number {
  let h1 = 0xdeadbeef ^ seed;
  let h2 = 0x41c6ce57 ^ seed;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return 4294967296 * (2097151 & h2) + (h1 >>> 0);
}

/** Deterministic hex digest of the given length (git-like ids). */
export function hexDigest(str: string, len = 40): string {
  let out = '';
  for (let i = 0; out.length < len; i++) out += hash53(str, i).toString(16).padStart(14, '0');
  return out.slice(0, len);
}

/** Shannon entropy in bits per character. */
export function entropy(s: string): number {
  if (!s) return 0;
  const freq: Record<string, number> = {};
  for (const c of s) freq[c] = (freq[c] ?? 0) + 1;
  let e = 0;
  for (const k in freq) {
    const p = freq[k] / s.length;
    e -= p * Math.log2(p);
  }
  return e;
}

// ---------- semver ----------

export type Ver = [number, number, number];

export function parseVer(v: string): Ver | null {
  const m = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?/.exec(v.trim());
  if (!m) return null;
  return [Number(m[1]), Number(m[2] ?? 0), Number(m[3] ?? 0)];
}

export function cmpVer(a: string, b: string): number {
  const x = parseVer(a);
  const y = parseVer(b);
  if (!x || !y) return 0;
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] - y[i];
  return 0;
}

function satisfiesOne(v: string, range: string): boolean {
  const r = range.trim();
  if (r === '' || r === '*' || r === 'latest' || r === 'x') return true;
  const parts = r.split(/\s+/);
  if (parts.length > 1) return parts.every((p) => satisfiesOne(v, p));
  const pv = parseVer(v);
  if (!pv) return false;
  const op = /^(\^|~|>=|<=|>|<|=)?/.exec(r)![1] ?? '';
  const base = r.slice(op.length);
  const bv = parseVer(base);
  if (!bv) return false;
  const c = cmpVer(v, base);
  switch (op) {
    case '^':
      if (c < 0) return false;
      if (bv[0] > 0) return pv[0] === bv[0];
      if (bv[1] > 0) return pv[0] === 0 && pv[1] === bv[1];
      return pv[0] === 0 && pv[1] === 0 && pv[2] === bv[2];
    case '~':
      return c >= 0 && pv[0] === bv[0] && pv[1] === bv[1];
    case '>=':
      return c >= 0;
    case '<=':
      return c <= 0;
    case '>':
      return c > 0;
    case '<':
      return c < 0;
    default:
      return c === 0;
  }
}

export function satisfies(v: string, range: string): boolean {
  return range.split('||').some((r) => satisfiesOne(v, r));
}

export function maxSatisfying(versions: string[], range: string): string | null {
  const ok = versions.filter((v) => satisfies(v, range)).sort(cmpVer);
  return ok.length ? ok[ok.length - 1] : null;
}

// ---------- text helpers ----------

/** Render a box-drawing table (Trivy style). */
export function boxTable(headers: string[], rows: string[][]): string[] {
  const widths = headers.map((h, i) => Math.max(h.length, ...rows.map((r) => (r[i] ?? '').length)));
  const line = (l: string, m: string, r: string) => l + widths.map((w) => '─'.repeat(w + 2)).join(m) + r;
  const row = (cells: string[]) => '│' + cells.map((c, i) => ' ' + (c ?? '').padEnd(widths[i]) + ' ').join('│') + '│';
  const out = [line('┌', '┬', '┐'), row(headers), line('├', '┼', '┤')];
  rows.forEach((r, i) => {
    out.push(row(r));
    if (i < rows.length - 1) out.push(line('├', '┼', '┤'));
  });
  out.push(line('└', '┴', '┘'));
  return out;
}

export function clock(d = new Date()): string {
  let h = d.getHours();
  const ap = h >= 12 ? 'PM' : 'AM';
  h = h % 12 || 12;
  return `${h}:${String(d.getMinutes()).padStart(2, '0')}${ap}`;
}

/** Minimal line diff (LCS) producing unified-diff style lines. */
export function diffLines(a: string, b: string): string[] {
  const x = a === '' ? [] : a.split('\n');
  const y = b === '' ? [] : b.split('\n');
  const n = x.length;
  const m = y.length;
  if (n * m > 400000) return [`- (${n} lines)`, `+ (${m} lines)`];
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--)
    for (let j = m - 1; j >= 0; j--) dp[i][j] = x[i] === y[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const out: string[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (x[i] === y[j]) {
      out.push(' ' + x[i]);
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) out.push('-' + x[i++]);
    else out.push('+' + y[j++]);
  }
  while (i < n) out.push('-' + x[i++]);
  while (j < m) out.push('+' + y[j++]);
  const keep = new Set<number>();
  out.forEach((l, k) => {
    if (l[0] !== ' ') for (let d = -2; d <= 2; d++) keep.add(k + d);
  });
  const res: string[] = [];
  let last = -10;
  out.forEach((l, k) => {
    if (!keep.has(k)) return;
    if (k !== last + 1) res.push('@@');
    res.push(l);
    last = k;
  });
  return res;
}

/** Split a shell-like command line into argv, honouring quotes. */
export function argv(cmd: string): string[] {
  const out: string[] = [];
  let cur = '';
  let q: string | null = null;
  let has = false;
  for (const c of cmd) {
    if (q) {
      if (c === q) q = null;
      else cur += c;
    } else if (c === '"' || c === "'") {
      q = c;
      has = true;
    } else if (/\s/.test(c)) {
      if (cur || has) out.push(cur);
      cur = '';
      has = false;
    } else cur += c;
  }
  if (cur || has) out.push(cur);
  return out;
}

export const C = {
  red: (s: string) => `\x1b[31m${s}\x1b[0m`,
  green: (s: string) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s: string) => `\x1b[33m${s}\x1b[0m`,
  blue: (s: string) => `\x1b[34m${s}\x1b[0m`,
  magenta: (s: string) => `\x1b[35m${s}\x1b[0m`,
  cyan: (s: string) => `\x1b[36m${s}\x1b[0m`,
  gray: (s: string) => `\x1b[90m${s}\x1b[0m`,
  bold: (s: string) => `\x1b[1m${s}\x1b[0m`,
};

export function sevColor(sev: string, s = sev): string {
  switch (sev) {
    case 'CRITICAL':
      return C.magenta(s);
    case 'HIGH':
      return C.red(s);
    case 'MEDIUM':
      return C.yellow(s);
    case 'LOW':
      return C.blue(s);
    default:
      return C.gray(s);
  }
}
