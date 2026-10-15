import type { Files, Finding, Severity } from './types';

// Semgrep-style SAST rules (pattern based) with nosemgrep suppression support.

export interface SastRule {
  id: string;
  severity: 'ERROR' | 'WARNING' | 'INFO';
  langs: RegExp;
  message: string;
  cwe: string;
  owasp: string;
  fix: string;
  match: (line: string) => boolean;
}

const SQL_IN_STRING = /(["'`])[^"'`]*\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b/i;

export const SAST_RULES: SastRule[] = [
  {
    id: 'javascript.lang.security.audit.sqli.node-postgres-sqli',
    severity: 'ERROR',
    langs: /\.(js|ts)$/,
    message: 'Detected string concatenation with a non-literal variable in a node-postgres SQL statement. This could lead to SQL injection if the variable is user-controlled. Use parameterized queries instead: client.query(\'SELECT $1 from table\', [userinput]).',
    cwe: 'CWE-89: SQL Injection',
    owasp: 'A03:2021 - Injection',
    fix: "Use a parameterised query: db.query('SELECT ... WHERE id = $1', [value])",
    match: (l) => SQL_IN_STRING.test(l) && (/["'`]\s*\+\s*[A-Za-z_$(]/.test(l) || /[\w$)\]]\s*\+\s*["'`]/.test(l) || /`[^`]*\$\{[^}]+\}[^`]*`/.test(l)),
  },
  {
    id: 'javascript.browser.security.eval-detected',
    severity: 'WARNING',
    langs: /\.(js|ts)$/,
    message: 'Detected the use of eval(). eval() can be dangerous if used to evaluate dynamic content. If this content can be input from outside the program, this may be a code injection vulnerability.',
    cwe: 'CWE-95: Eval Injection',
    owasp: 'A03:2021 - Injection',
    fix: 'Never evaluate input. Parse it into a strict type (e.g. a number), validate the range and compute in code.',
    match: (l) => /(^|[^\w.])eval\s*\(/.test(l) || /new\s+Function\s*\(/.test(l),
  },
  {
    id: 'javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret',
    severity: 'WARNING',
    langs: /\.(js|ts)$/,
    message: 'A hard-coded credential was detected. Provide credentials through environment variables or a secrets manager.',
    cwe: 'CWE-798: Use of Hard-coded Credentials',
    owasp: 'A07:2021 - Identification and Authentication Failures',
    fix: 'Load the signing secret from process.env.',
    match: (l) => /jwt\.(sign|verify)\s*\([^,]+,\s*["'`]/.test(l),
  },
  {
    id: 'javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-httponly',
    severity: 'WARNING',
    langs: /\.(js|ts)$/,
    message: 'Session middleware settings: `httpOnly` is disabled. It keeps the cookie away from client JavaScript, helping to protect against cross-site scripting.',
    cwe: 'CWE-522: Insufficiently Protected Credentials',
    owasp: 'A07:2021 - Identification and Authentication Failures',
    fix: "Set cookie: { httpOnly: true, secure: true, sameSite: 'lax' }",
    match: (l) => /httpOnly\s*:\s*false/.test(l),
  },
  {
    id: 'python.lang.security.deserialization.pickle.avoid-pickle',
    severity: 'WARNING',
    langs: /\.py$/,
    message: 'Avoid using `pickle` for untrusted data; deserialising it can run code. Use JSON instead.',
    cwe: 'CWE-502: Deserialization of Untrusted Data',
    owasp: 'A08:2021 - Software and Data Integrity Failures',
    fix: 'Use json.loads() for untrusted data.',
    match: (l) => /\bpickle\.loads?\s*\(/.test(l),
  },
];

export interface SastMatch {
  rule: SastRule;
  file: string;
  line: number;
  code: string;
  suppressed: boolean;
}

function suppressedBy(comment: string, ruleId: string): boolean {
  const m = /nosemgrep(?::\s*([\w.,-]+))?/.exec(comment);
  if (!m) return false;
  if (!m[1]) return true;
  return m[1].split(',').some((id) => id.trim() && ruleId.endsWith(id.trim()));
}

export function runSast(files: Files): { matches: SastMatch[]; scanned: number } {
  const matches: SastMatch[] = [];
  let scanned = 0;
  const ignored = (files['.semgrepignore'] ?? '').split('\n').map((s) => s.trim().replace(/^\//, '').replace(/\*+$/, '')).filter(Boolean);
  for (const [file, text] of Object.entries(files)) {
    if (!/\.(js|ts|py)$/.test(file) || file.startsWith('node_modules/') || ignored.some((p) => file.startsWith(p))) continue;
    scanned++;
    const lines = text.split('\n');
    lines.forEach((l, i) => {
      if (/^\s*(\/\/|#|\*)/.test(l)) return;
      for (const r of SAST_RULES) {
        if (!r.langs.test(file) || !r.match(l)) continue;
        const sup = suppressedBy(l, r.id) || (i > 0 && suppressedBy(lines[i - 1], r.id));
        matches.push({ rule: r, file, line: i + 1, code: l.trim(), suppressed: sup });
      }
    });
  }
  return { matches, scanned };
}

const sevMap: Record<string, Severity> = { ERROR: 'HIGH', WARNING: 'MEDIUM', INFO: 'LOW' };

export function sastToFinding(m: SastMatch): Finding {
  return {
    tool: 'semgrep',
    ruleId: m.rule.id,
    severity: sevMap[m.rule.severity],
    title: m.rule.message.split('. ')[0] + '.',
    file: m.file,
    line: m.line,
    detail: `${m.rule.cwe} · ${m.rule.owasp}`,
    remediation: m.rule.fix,
  };
}
