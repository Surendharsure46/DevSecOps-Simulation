import type { Files, Finding, Severity } from './types';
import { cmpVer, maxSatisfying, satisfies } from './util';

// Offline npm registry + advisory snapshot used by `npm`, `npm audit`, `trivy fs` and `syft`.

export const REGISTRY: Record<string, string[]> = {
  express: ['4.16.4', '4.17.1', '4.18.2', '4.19.2', '4.21.2', '5.1.0'],
  lodash: ['4.17.15', '4.17.19', '4.17.20', '4.17.21'],
  jsonwebtoken: ['8.5.1', '9.0.0', '9.0.2'],
  axios: ['0.21.0', '0.21.1', '0.21.4', '0.27.2', '1.6.0', '1.7.9'],
  minimist: ['1.2.5', '1.2.6', '1.2.8'],
  helmet: ['6.2.0', '7.1.0', '8.0.0'],
  pg: ['8.7.1', '8.11.3', '8.13.1'],
  'express-session': ['1.17.1', '1.17.3', '1.18.1'],
  'express-rate-limit': ['7.4.1'],
  dotenv: ['16.0.3', '16.4.7'],
  jest: ['29.7.0'],
  supertest: ['7.0.0'],
};

export interface Advisory {
  id: string;
  ghsa: string;
  pkg: string;
  vulnerable: string;
  fixed: string;
  severity: Severity;
  cvss: number;
  title: string;
}

export const ADVISORIES: Advisory[] = [
  { id: 'CVE-2021-23337', ghsa: 'GHSA-35jh-r3h4-6jhm', pkg: 'lodash', vulnerable: '<4.17.21', fixed: '4.17.21', severity: 'HIGH', cvss: 7.2, title: 'lodash: command injection via template' },
  { id: 'CVE-2020-8203', ghsa: 'GHSA-p6mc-m468-83gw', pkg: 'lodash', vulnerable: '<4.17.19', fixed: '4.17.19', severity: 'HIGH', cvss: 7.4, title: 'lodash: prototype pollution in zipObjectDeep' },
  { id: 'CVE-2022-23540', ghsa: 'GHSA-qwph-4952-7xr6', pkg: 'jsonwebtoken', vulnerable: '<9.0.0', fixed: '9.0.0', severity: 'HIGH', cvss: 7.6, title: 'jsonwebtoken: insecure default algorithm in verify()' },
  { id: 'CVE-2022-23541', ghsa: 'GHSA-hjrf-2m68-5959', pkg: 'jsonwebtoken', vulnerable: '<9.0.0', fixed: '9.0.0', severity: 'MEDIUM', cvss: 6.3, title: 'jsonwebtoken: insecure key retrieval function' },
  { id: 'CVE-2021-3749', ghsa: 'GHSA-cph5-m8f7-6c5x', pkg: 'axios', vulnerable: '<0.21.2', fixed: '0.21.2', severity: 'HIGH', cvss: 7.5, title: 'axios: ReDoS in trim' },
  { id: 'CVE-2020-28168', ghsa: 'GHSA-4w2v-q235-vp99', pkg: 'axios', vulnerable: '<0.21.1', fixed: '0.21.1', severity: 'MEDIUM', cvss: 5.9, title: 'axios: server-side request forgery via redirect' },
  { id: 'CVE-2023-45857', ghsa: 'GHSA-wf5p-g6vw-rhxx', pkg: 'axios', vulnerable: '>=0.8.1 <1.6.0', fixed: '1.6.0', severity: 'MEDIUM', cvss: 6.5, title: 'axios: XSRF-TOKEN exposed to third-party hosts' },
  { id: 'CVE-2021-44906', ghsa: 'GHSA-xvch-5gv4-984h', pkg: 'minimist', vulnerable: '<1.2.6', fixed: '1.2.6', severity: 'CRITICAL', cvss: 9.8, title: 'minimist: prototype pollution' },
  { id: 'CVE-2024-29041', ghsa: 'GHSA-rv95-896h-c2vc', pkg: 'express', vulnerable: '<4.19.2', fixed: '4.19.2', severity: 'MEDIUM', cvss: 6.1, title: 'express: open redirect in malformed URLs' },
  { id: 'CVE-2024-43796', ghsa: 'GHSA-qw6h-vgh9-j6wx', pkg: 'express', vulnerable: '<4.20.0', fixed: '4.20.0', severity: 'LOW', cvss: 5.0, title: 'express: XSS via response.redirect()' },
  { id: 'CVE-2022-24999', ghsa: 'GHSA-hrpp-h998-j3pp', pkg: 'express', vulnerable: '<4.17.3', fixed: '4.17.3', severity: 'HIGH', cvss: 7.5, title: 'qs (via express): prototype poisoning hangs the process' },
];

export function latest(pkg: string): string | null {
  const v = REGISTRY[pkg];
  return v ? [...v].sort(cmpVer)[v.length - 1] : null;
}

export interface PkgJson {
  name?: string;
  version?: string;
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  overrides?: Record<string, string>;
}

export function readPkg(files: Files): { pkg: PkgJson | null; error: string | null } {
  const src = files['package.json'];
  if (src === undefined) return { pkg: null, error: "ENOENT: no such file or directory, open 'package.json'" };
  try {
    return { pkg: JSON.parse(src) as PkgJson, error: null };
  } catch (e) {
    return { pkg: null, error: `Unexpected token in package.json: ${(e as Error).message}` };
  }
}

export function allDeps(pkg: PkgJson): Record<string, string> {
  return { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
}

export function readLock(files: Files): Record<string, string> | null {
  const src = files['package-lock.json'];
  if (!src) return null;
  try {
    const j = JSON.parse(src) as { packages?: Record<string, { version?: string }> };
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(j.packages ?? {})) if (k.startsWith('node_modules/') && v.version) out[k.slice(13)] = v.version;
    return out;
  } catch {
    return null;
  }
}

export function writeLock(pkg: PkgJson, installed: Record<string, string>): string {
  const packages: Record<string, unknown> = {
    '': { name: pkg.name ?? 'app', version: pkg.version ?? '1.0.0', dependencies: pkg.dependencies ?? {}, devDependencies: pkg.devDependencies ?? {} },
  };
  const dev = pkg.devDependencies ?? {};
  for (const name of Object.keys(installed).sort())
    packages[`node_modules/${name}`] = { version: installed[name], resolved: `https://registry.npmjs.org/${name}/-/${name}-${installed[name]}.tgz`, ...(name in dev ? { dev: true } : {}) };
  return JSON.stringify({ name: pkg.name ?? 'app', version: pkg.version ?? '1.0.0', lockfileVersion: 3, requires: true, packages }, null, 2) + '\n';
}

/** Resolve package.json ranges, preferring versions already in the lockfile. */
export function resolve(pkg: PkgJson, lock: Record<string, string> | null): { installed: Record<string, string>; errors: string[] } {
  const installed: Record<string, string> = {};
  const errors: string[] = [];
  for (const [name, range] of Object.entries(allDeps(pkg))) {
    const versions = REGISTRY[name];
    if (!versions) {
      errors.push(`npm ERR! code E404\nnpm ERR! 404 Not Found - GET https://registry.npmjs.org/${name} - Not found`);
      continue;
    }
    const effective = pkg.overrides?.[name] ?? range;
    if (lock?.[name] && satisfies(lock[name], effective)) {
      installed[name] = lock[name];
      continue;
    }
    const v = maxSatisfying(versions, effective);
    if (!v) {
      errors.push(`npm ERR! code ETARGET\nnpm ERR! notarget No matching version found for ${name}@${effective}.`);
      continue;
    }
    installed[name] = v;
  }
  return { installed, errors };
}

export function lockInSync(pkg: PkgJson, lock: Record<string, string> | null): string[] {
  if (!lock) return ['Missing: package-lock.json'];
  const problems: string[] = [];
  for (const [name, range] of Object.entries(allDeps(pkg))) {
    const v = lock[name];
    if (!v) problems.push(`Missing: ${name}@${range} from lock file`);
    else if (!satisfies(v, pkg.overrides?.[name] ?? range)) problems.push(`Invalid: lock file's ${name}@${v} does not satisfy ${name}@${range}`);
  }
  return problems;
}

export interface VulnHit {
  adv: Advisory;
  installed: string;
}

const ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

export function auditInstalled(installed: Record<string, string>): VulnHit[] {
  const hits: VulnHit[] = [];
  for (const [name, v] of Object.entries(installed)) for (const adv of ADVISORIES) if (adv.pkg === name && satisfies(v, adv.vulnerable)) hits.push({ adv, installed: v });
  return hits.sort((a, b) => ORDER.indexOf(a.adv.severity) - ORDER.indexOf(b.adv.severity) || a.adv.pkg.localeCompare(b.adv.pkg));
}

export function vulnToFinding(h: VulnHit): Finding {
  return {
    tool: 'trivy-fs',
    ruleId: h.adv.id,
    severity: h.adv.severity,
    title: h.adv.title,
    file: 'package-lock.json',
    pkg: h.adv.pkg,
    installed: h.installed,
    fixed: h.adv.fixed,
    detail: `${h.adv.ghsa} · CVSS ${h.adv.cvss}`,
    remediation: `Upgrade ${h.adv.pkg} to ${h.adv.fixed} or later, run npm install, re-run the tests.`,
  };
}

export function sbomCycloneDx(pkg: PkgJson, installed: Record<string, string>, tool = 'trivy'): string {
  const components = Object.entries(installed)
    .sort()
    .map(([n, v]) => ({ 'bom-ref': `pkg:npm/${n}@${v}`, type: 'library', name: n, version: v, purl: `pkg:npm/${n}@${v}` }));
  return (
    JSON.stringify(
      { bomFormat: 'CycloneDX', specVersion: '1.5', version: 1, metadata: { component: { type: 'application', name: pkg.name ?? 'app', version: pkg.version ?? '0.0.0' }, tools: [{ name: tool }] }, components },
      null,
      2,
    ) + '\n'
  );
}
