import type { Commit, Files, Finding } from './types';
import { entropy } from './util';

// Gitleaks-style secret detection: rule regexes, entropy thresholds, stopwords and
// fingerprints compatible with a .gitleaksignore file.

interface Rule {
  id: string;
  description: string;
  re: RegExp;
  group: number;
  minEntropy?: number;
}

const RULES: Rule[] = [
  { id: 'aws-access-token', description: 'Identified a pattern that may indicate AWS credentials, risking unauthorized cloud resource access.', re: /\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b/g, group: 1, minEntropy: 3 },
  { id: 'github-pat', description: 'Uncovered a GitHub Personal Access Token, potentially leading to unauthorized repository access.', re: /\b(ghp_[0-9a-zA-Z]{36})\b/g, group: 1 },
  { id: 'private-key', description: 'Identified a Private Key, which may compromise cryptographic security.', re: /(-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----)/g, group: 1 },
  {
    id: 'generic-api-key',
    description: 'Detected a Generic API Key, potentially exposing access to various services.',
    re: /(?:secret|password|passwd|pwd|token|api[_-]?key|access[_-]?key)[\w.-]{0,20}\s*(?::|=|:=|=>)\s*(["'`]?)([^\s"'`;,)]{8,150})\1/gi,
    group: 2,
    minEntropy: 3.0,
  },
];

const STOPWORDS = ['example', 'changeme', 'placeholder', 'your-', 'your_', '<', 'xxxx', 'process.env', 'os.environ', '${', 'secrets.', 'getenv', 'redacted', 'removed', 'dummy', 'sample'];

export interface Leak {
  ruleId: string;
  description: string;
  file: string;
  line: number;
  match: string;
  secret: string;
  entropy: number;
  commit?: Commit;
  fingerprint: string;
}

export function scanText(file: string, text: string): Omit<Leak, 'fingerprint' | 'commit'>[] {
  const out: Omit<Leak, 'fingerprint' | 'commit'>[] = [];
  if (file.endsWith('package-lock.json') || file === '.gitleaksignore') return out;
  text.split('\n').forEach((ln, i) => {
    if (/gitleaks:allow/.test(ln)) return;
    const seen = new Set<string>();
    for (const r of RULES) {
      r.re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = r.re.exec(ln))) {
        const secret = m[r.group];
        if (!secret || seen.has(secret)) continue;
        const lower = secret.toLowerCase();
        if (STOPWORDS.some((w) => lower.includes(w))) continue;
        const generic = r.id === 'generic-api-key';
        if (generic && /^[A-Z_]+$/.test(secret)) continue;
        // unquoted identifiers in source code are variable references, not literals
        if (generic && !m[1] && /\.(js|ts|py)$/.test(file) && /^[A-Za-z_$][\w$.[\]]*$/.test(secret)) continue;
        const e = entropy(secret);
        if (r.minEntropy && e < r.minEntropy) continue;
        if (generic && RULES.slice(0, -1).some((o) => new RegExp(o.re.source).test(secret))) continue;
        seen.add(secret);
        out.push({ ruleId: r.id, description: r.description, file, line: i + 1, match: m[0], secret, entropy: Math.round(e * 100) / 100 });
      }
    }
  });
  return out;
}

export function scanFiles(files: Files): Leak[] {
  const leaks: Leak[] = [];
  for (const [f, t] of Object.entries(files)) for (const l of scanText(f, t)) leaks.push({ ...l, fingerprint: `${f}:${l.ruleId}:${l.line}` });
  return applyIgnore(leaks, files);
}

/** Scan every commit, reporting each secret at the commit that introduced it. */
export function scanHistory(commits: Commit[], ignoreSource: Files): Leak[] {
  const leaks: Leak[] = [];
  const known = new Set<string>();
  for (const c of [...commits].reverse()) {
    const parent = commits.find((p) => p.id === c.parent);
    for (const [f, t] of Object.entries(c.files)) {
      if (parent && parent.files[f] === t) continue;
      for (const l of scanText(f, t)) {
        const key = `${f}|${l.secret}`;
        if (known.has(key)) continue;
        known.add(key);
        leaks.push({ ...l, commit: c, fingerprint: `${c.id}:${f}:${l.ruleId}:${l.line}` });
      }
    }
  }
  return applyIgnore(leaks, ignoreSource);
}

function applyIgnore(leaks: Leak[], files: Files): Leak[] {
  const ignore = new Set(
    (files['.gitleaksignore'] ?? '')
      .split('\n')
      .map((s) => s.trim())
      .filter((s) => s && !s.startsWith('#')),
  );
  return leaks.filter((l) => !ignore.has(l.fingerprint));
}

export function redact(s: string): string {
  if (s.length <= 8) return '****';
  return s.slice(0, 4) + '*'.repeat(Math.max(4, s.length - 8)) + s.slice(-4);
}

export function leakToFinding(l: Leak): Finding {
  return {
    tool: 'gitleaks',
    ruleId: l.ruleId,
    severity: l.ruleId === 'generic-api-key' ? 'HIGH' : 'CRITICAL',
    title: l.description,
    file: l.file,
    line: l.line,
    detail: `Secret ${redact(l.secret)} (entropy ${l.entropy})${l.commit ? ` — introduced in ${l.commit.id.slice(0, 7)} "${l.commit.message}"` : ''}`,
    remediation: 'Deactivate/rotate the credential first, then load it from the environment and remove it from Git history.',
  };
}
