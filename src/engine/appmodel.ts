import type { Files } from './types';
import { SAST_RULES } from './sast';

// Static model of the ShopFlow Express app: used by unit tests, the staging
// environment and DAST so that behaviour follows the learner's real code.

export function routeBlock(src: string | undefined, method: string, path: string): string | null {
  if (!src) return null;
  const esc = path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const m = new RegExp(`(router|app)\\.${method}\\(\\s*['"\`]${esc}['"\`]`).exec(src);
  if (!m) return null;
  const rest = src.slice(m.index);
  const next = rest.slice(1).search(/\n\s*(router|app)\.(get|post|put|delete|patch|use)\(|\nmodule\.exports/);
  return next < 0 ? rest : rest.slice(0, next + 1);
}

const sqli = SAST_RULES.find((r) => r.id.endsWith('node-postgres-sqli'))!;
const codeLines = (block: string) => block.split('\n').filter((l) => !/^\s*\/\//.test(l));

export function sqlInjectable(block: string | null): boolean {
  return !!block && codeLines(block).some((l) => sqli.match(l));
}

export function parameterised(block: string | null): boolean {
  if (!block) return false;
  return /\.query\(\s*(['"`])[^'"`]*\$\d[^'"`]*\1\s*,\s*\[[^\]]+\]/.test(block) || /\.query\(\s*\w+\s*,\s*\[[^\]]+\]/.test(block);
}

export function usesEval(block: string | null): boolean {
  return !!block && codeLines(block).some((l) => /(^|[^\w.])eval\s*\(/.test(l) || /new\s+Function\s*\(/.test(l));
}

export function requires(src: string | undefined): string[] {
  if (!src) return [];
  return [...src.matchAll(/require\(\s*['"]([^./'"][^'"]*)['"]\s*\)/g)].map((m) => m[1]);
}

const BUILTINS = ['fs', 'path', 'crypto', 'child_process', 'http', 'https', 'url', 'os'];

/** Simulate `node src/server.js` module loading: returns an error message or null. */
export function moduleLoadError(files: Files, installed: Record<string, string>, entry = 'src/server.js'): string | null {
  const seen = new Set<string>();
  const visit = (path: string): string | null => {
    if (seen.has(path)) return null;
    seen.add(path);
    const src = files[path];
    if (src === undefined) return `Error: Cannot find module './${path}'`;
    for (const r of requires(src)) if (!BUILTINS.includes(r) && !installed[r]) return `Error: Cannot find module '${r}'\nRequire stack:\n- /app/${path}`;
    for (const m of src.matchAll(/require\(\s*['"](\.\.?\/[^'"]+)['"]\s*\)/g)) {
      const base = path.split('/').slice(0, -1);
      for (const seg of m[1].split('/')) {
        if (seg === '..') base.pop();
        else if (seg !== '.') base.push(seg);
      }
      let target = base.join('/');
      if (!target.endsWith('.js')) target = files[target + '.js'] !== undefined ? target + '.js' : target + '/index.js';
      const e = visit(target);
      if (e) return e;
    }
    return null;
  };
  const err = visit(entry);
  if (err) return err;
  if (installed.express?.startsWith('5.') && /\.(get|use|all)\(\s*['"]\*['"]/.test(files[entry] ?? ''))
    return 'TypeError: Missing parameter name at 1: https://git.new/pathToRegexpError\n    at name (/app/node_modules/path-to-regexp/dist/index.js:73:19)';
  return null;
}

export function helmetEnabled(files: Files, installed: Record<string, string>): boolean {
  const s = files['src/server.js'] ?? '';
  return !!installed.helmet && /require\(['"]helmet['"]\)/.test(s) && /app\.use\(\s*helmet\(/.test(s);
}

export function poweredByHidden(files: Files, installed: Record<string, string>): boolean {
  return helmetEnabled(files, installed) || /app\.disable\(\s*['"]x-powered-by['"]\s*\)/.test(files['src/server.js'] ?? '');
}

export interface CookieCfg {
  present: boolean;
  httpOnly: boolean;
  secure: boolean;
  sameSite: string | null;
}

export function sessionCookie(files: Files, installed: Record<string, string>): CookieCfg {
  const s = files['src/server.js'] ?? '';
  if (!/require\(['"]express-session['"]\)/.test(s) || !installed['express-session']) return { present: false, httpOnly: true, secure: false, sameSite: null };
  const cookie = /cookie\s*:\s*\{([^}]*)\}/.exec(s)?.[1] ?? '';
  return {
    present: true,
    httpOnly: !/httpOnly\s*:\s*false/.test(cookie),
    secure: /secure\s*:\s*(true|['"]auto['"])/.test(cookie),
    sameSite: /sameSite\s*:\s*['"](\w+)['"]/.exec(cookie)?.[1] ?? (/sameSite\s*:\s*true/.test(cookie) ? 'Strict' : null),
  };
}
