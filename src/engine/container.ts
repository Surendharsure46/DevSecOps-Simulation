import type { Files, Finding, ImageInfo, Severity } from './types';
import { auditInstalled, readLock, readPkg, resolve } from './sca';

// Dockerfile parsing, Hadolint / Trivy-config rules, a build simulator with real failure
// modes (missing shell, wrong package manager, missing lockfile, unknown base image) and
// `docker run` start-up checks.

export interface Instr {
  cmd: string;
  args: string;
  line: number;
  ignore: string[];
}

const KNOWN = ['FROM', 'RUN', 'CMD', 'LABEL', 'EXPOSE', 'ENV', 'ADD', 'COPY', 'ENTRYPOINT', 'VOLUME', 'USER', 'WORKDIR', 'ARG', 'ONBUILD', 'STOPSIGNAL', 'HEALTHCHECK', 'SHELL', 'MAINTAINER'];

export function parseDockerfile(src: string): { instrs: Instr[]; error: string | null } {
  const lines = src.split(/\r?\n/);
  const instrs: Instr[] = [];
  let pendingIgnore: string[] = [];
  for (let i = 0; i < lines.length; i++) {
    let l = lines[i].trim();
    if (!l) continue;
    if (l.startsWith('#')) {
      const m = /hadolint\s+ignore=([\w,\s]+)/.exec(l);
      if (m) pendingIgnore = m[1].split(',').map((s) => s.trim());
      continue;
    }
    const start = i;
    while (l.endsWith('\\') && i + 1 < lines.length) {
      i++;
      const next = lines[i].trim();
      if (next.startsWith('#')) continue;
      l = l.slice(0, -1) + ' ' + next;
    }
    const m = /^([A-Za-z]+)\s*(.*)$/.exec(l);
    const cmd = m?.[1].toUpperCase() ?? '';
    if (!m || !KNOWN.includes(cmd)) return { instrs, error: `dockerfile parse error on line ${start + 1}: unknown instruction: ${l.split(/\s/)[0]}` };
    instrs.push({ cmd, args: m[2].replace(/\s+/g, ' ').trim(), line: start + 1, ignore: pendingIgnore });
    pendingIgnore = [];
  }
  if (!instrs.length) return { instrs, error: 'the Dockerfile cannot be empty' };
  if (instrs[0].cmd !== 'FROM' && instrs[0].cmd !== 'ARG') return { instrs, error: 'failed to solve: no build stage in current context' };
  return { instrs, error: null };
}

// ---------- base images ----------

export interface OsVuln {
  pkg: string;
  id: string;
  severity: Severity;
  installed: string;
  fixed: string;
  title: string;
}

export interface Base {
  family: 'debian' | 'debian-slim' | 'alpine' | 'distroless';
  shell: boolean;
  pm: 'apt' | 'apk' | null;
  users: string[];
  size: number;
  entrypoint: string | null;
  vulns: OsVuln[];
  extraLow: number;
}

const ZLIB: OsVuln = { pkg: 'zlib1g', id: 'CVE-2023-45853', severity: 'CRITICAL', installed: '1:1.2.13.dfsg-1', fixed: '', title: 'zlib: integer overflow in zipOpenNewFileInZip4_6' };
const PERL: OsVuln = { pkg: 'perl-base', id: 'CVE-2023-31484', severity: 'HIGH', installed: '5.36.0-7+deb12u1', fixed: '', title: 'perl: CPAN.pm does not verify TLS certificates' };
const DEBIAN_FULL: OsVuln[] = [
  { pkg: 'libexpat1', id: 'CVE-2024-45492', severity: 'CRITICAL', installed: '2.5.0-1', fixed: '2.5.0-1+deb12u1', title: 'libexpat: integer overflow in nextScaffoldPart' },
  { pkg: 'libssl3', id: 'CVE-2024-5535', severity: 'CRITICAL', installed: '3.0.11-1~deb12u2', fixed: '3.0.14-1~deb12u1', title: 'openssl: SSL_select_next_proto buffer overread' },
  { pkg: 'libc6', id: 'CVE-2023-4911', severity: 'HIGH', installed: '2.36-9+deb12u1', fixed: '2.36-9+deb12u3', title: 'glibc: buffer overflow in ld.so (Looney Tunables)' },
  ZLIB,
  PERL,
  { pkg: 'git', id: 'CVE-2024-32002', severity: 'HIGH', installed: '1:2.39.2-1.1', fixed: '1:2.39.5-0+deb12u1', title: 'git: recursive clones on case-insensitive filesystems' },
];

const BASES: { re: RegExp; base: Base }[] = [
  { re: /^gcr\.io\/distroless\/nodejs(18|20|22)-debian1[12](:(latest|nonroot|debug))?$/, base: { family: 'distroless', shell: false, pm: null, users: ['root', 'nonroot', '65532'], size: 128, entrypoint: '/nodejs/bin/node', vulns: [], extraLow: 2 } },
  { re: /^node:(18|20|22|24)(\.\d+)*-alpine(3\.\d+)?$/, base: { family: 'alpine', shell: true, pm: 'apk', users: ['root', 'node', '1000'], size: 134, entrypoint: null, vulns: [{ pkg: 'busybox', id: 'CVE-2023-42366', severity: 'MEDIUM', installed: '1.36.1-r15', fixed: '1.36.1-r16', title: 'busybox: heap-buffer-overflow in awk' }], extraLow: 1 } },
  { re: /^node:(18|20|22|24)(\.\d+)*-(bookworm-)?slim$/, base: { family: 'debian-slim', shell: true, pm: 'apt', users: ['root', 'node', '1000'], size: 198, entrypoint: null, vulns: [ZLIB, PERL], extraLow: 19 } },
  { re: /^node:((18|20|22|24)(\.\d+)*(-bookworm)?|latest|lts|current)$/, base: { family: 'debian', shell: true, pm: 'apt', users: ['root', 'node', '1000'], size: 1100, entrypoint: null, vulns: DEBIAN_FULL, extraLow: 141 } },
];

export function lookupBase(image: string): Base | null {
  const ref = image.includes(':') || image.includes('@') ? image : `${image}:latest`;
  for (const b of BASES) if (b.re.test(ref)) return b.base;
  return null;
}

const APT_PKG_VULNS: Record<string, OsVuln> = {
  curl: { pkg: 'curl', id: 'CVE-2023-38545', severity: 'CRITICAL', installed: '7.88.1-10+deb12u1', fixed: '7.88.1-10+deb12u4', title: 'curl: heap buffer overflow in SOCKS5 proxy handshake' },
  vim: { pkg: 'vim', id: 'CVE-2023-4752', severity: 'HIGH', installed: '2:9.0.1378-2', fixed: '', title: 'vim: heap use-after-free in ins_compl_get_exp()' },
  wget: { pkg: 'wget', id: 'CVE-2024-38428', severity: 'CRITICAL', installed: '1.21.3-1+b2', fixed: '1.21.3-1+deb12u1', title: 'wget: misinterpretation of input' },
};

// ---------- lint: hadolint ----------

export interface LintHit {
  rule: string;
  level: 'error' | 'warning' | 'info' | 'style';
  line: number;
  msg: string;
}

export function lastUser(instrs: Instr[]): { user: string | null; line: number } {
  let u: string | null = null;
  let line = 0;
  for (const i of instrs) {
    if (i.cmd === 'FROM') {
      u = i.args.split(/\s+/)[0].endsWith(':nonroot') ? 'nonroot' : null;
      line = i.line;
    }
    if (i.cmd === 'USER') {
      u = i.args.split(':')[0];
      line = i.line;
    }
  }
  return { user: u, line };
}

export function hadolint(src: string, ignored: string[] = []): { hits: LintHit[]; error: string | null } {
  const { instrs, error } = parseDockerfile(src);
  if (error) return { hits: [], error };
  const hits: LintHit[] = [];
  const add = (i: Instr, rule: string, level: LintHit['level'], msg: string) => {
    if (!i.ignore.includes(rule) && !ignored.includes(rule)) hits.push({ rule, level, line: i.line, msg });
  };
  const stages = new Set<string>();
  for (const i of instrs) {
    if (i.cmd === 'FROM') {
      const [img, , alias] = i.args.split(/\s+/).filter((s) => !s.startsWith('--'));
      if (!stages.has(img.toLowerCase())) {
        if (img.endsWith(':latest')) add(i, 'DL3007', 'warning', 'Using latest is prone to errors if the image will ever update. Pin the version explicitly to a release tag');
        else if (!img.includes(':') && !img.includes('@') && img !== 'scratch') add(i, 'DL3006', 'warning', 'Always tag the version of an image explicitly');
      }
      if (alias) stages.add(alias.toLowerCase());
    }
    if (i.cmd === 'ADD' && !/https?:\/\//.test(i.args) && !/\.(tar|tgz|tar\.gz|zip)\b/.test(i.args)) add(i, 'DL3020', 'error', 'Use COPY instead of ADD for files and folders');
    if (i.cmd === 'WORKDIR' && !i.args.startsWith('/') && !i.args.startsWith('$')) add(i, 'DL3000', 'error', 'Use absolute WORKDIR');
    if ((i.cmd === 'CMD' || i.cmd === 'ENTRYPOINT') && !i.args.startsWith('[')) add(i, 'DL3025', 'warning', 'Use arguments JSON notation for CMD and ENTRYPOINT arguments');
    if (i.cmd === 'RUN') {
      const a = i.args;
      if (/apt-get\s+(-\S+\s+)*install/.test(a)) {
        const pkgs = a.split(/apt-get\s+(?:-\S+\s+)*install/)[1]?.split(/&&|;|\|/)[0].trim().split(/\s+/).filter((p) => p && !p.startsWith('-')) ?? [];
        if (pkgs.some((p) => !p.includes('='))) add(i, 'DL3008', 'warning', 'Pin versions in apt get install. Instead of `apt-get install <package>` use `apt-get install <package>=<version>`');
        if (!/--no-install-recommends/.test(a)) add(i, 'DL3015', 'info', 'Avoid additional packages by specifying `--no-install-recommends`');
        if (!/rm -rf \/var\/lib\/apt\/lists/.test(a)) add(i, 'DL3009', 'info', 'Delete the apt-get lists after installing something');
      }
      if (/apk\s+add/.test(a) && !/--no-cache/.test(a)) add(i, 'DL3019', 'info', 'Use the `--no-cache` switch to avoid the need to use `--update` and remove `/var/cache/apk/*`');
      if (/\bsudo\b/.test(a)) add(i, 'DL3004', 'error', 'Do not use sudo as it leads to unpredictable behavior');
    }
  }
  const lu = lastUser(instrs);
  if (lu.user === 'root' || lu.user === '0') add(instrs.find((x) => x.line === lu.line)!, 'DL3002', 'warning', 'Last USER should not be root');
  return { hits, error: null };
}

export const hadolintSeverity: Record<LintHit['level'], Severity> = { error: 'HIGH', warning: 'MEDIUM', info: 'LOW', style: 'INFO' };

// ---------- trivy config (misconfiguration) ----------

export interface Misconf {
  id: string;
  avd: string;
  severity: Severity;
  title: string;
  message: string;
  line: number;
  resolution: string;
}

export function trivyConfigDockerfile(src: string): Misconf[] {
  const { instrs, error } = parseDockerfile(src);
  if (error) return [];
  const out: Misconf[] = [];
  const finalFrom = [...instrs].reverse().find((i) => i.cmd === 'FROM');
  if (finalFrom) {
    const img = finalFrom.args.split(/\s+/).filter((s) => !s.startsWith('--'))[0];
    if (img.endsWith(':latest') || (!img.includes(':') && !img.includes('@')))
      out.push({ id: 'DS001', avd: 'AVD-DS-0001', severity: 'MEDIUM', title: "':latest' tag used", message: `Specify a tag in the 'FROM' statement for image '${img.split(':')[0]}'`, line: finalFrom.line, resolution: "Add a tag to the image in the 'FROM' statement" });
  }
  const lu = lastUser(instrs);
  if (!lu.user || lu.user === 'root' || lu.user === '0')
    out.push({ id: 'DS002', avd: 'AVD-DS-0002', severity: 'HIGH', title: "Image user should not be 'root'", message: lu.user ? "Last USER command in Dockerfile should not be 'root'" : 'Specify at least 1 USER command in Dockerfile with non-root user as argument', line: lu.user ? lu.line : 1, resolution: "Add 'USER <non root user name>' line to the Dockerfile" });
  for (const i of instrs) {
    if (i.cmd === 'ADD' && !/https?:\/\//.test(i.args) && !/\.(tar|tgz|zip)/.test(i.args))
      out.push({ id: 'DS005', avd: 'AVD-DS-0005', severity: 'LOW', title: 'ADD instead of COPY', message: `Consider using 'COPY ${i.args}' command instead of 'ADD ${i.args}'`, line: i.line, resolution: 'Use COPY instead of ADD' });
    if (i.cmd === 'RUN' && /apt-get\s+(-\S+\s+)*install/.test(i.args) && !/--no-install-recommends/.test(i.args))
      out.push({ id: 'DS029', avd: 'AVD-DS-0029', severity: 'HIGH', title: "'apt-get' missing '--no-install-recommends'", message: `'--no-install-recommends' flag is missed: '${i.args.slice(0, 60)}'`, line: i.line, resolution: "Add '--no-install-recommends' flag to 'apt-get'" });
    if ((i.cmd === 'ENV' || i.cmd === 'ARG') && /(PASSWORD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY)\w*\s*[= ]\s*\S+/i.test(i.args))
      out.push({ id: 'DS031', avd: 'AVD-DS-0031', severity: 'CRITICAL', title: 'Secrets passed via `build-args` or envs', message: `Possible exposure of secret env "${i.args.split(/[= ]/)[0]}" in ${i.cmd}`, line: i.line, resolution: 'Inject secrets at runtime (env from a secret store); never bake them into image layers.' });
  }
  if (!instrs.some((i) => i.cmd === 'HEALTHCHECK'))
    out.push({ id: 'DS026', avd: 'AVD-DS-0026', severity: 'LOW', title: 'No HEALTHCHECK defined', message: 'Add HEALTHCHECK instruction in your Dockerfile', line: 1, resolution: 'Add HEALTHCHECK instruction in Dockerfile' });
  return out;
}

// ---------- docker build ----------

interface Stage {
  name: string | null;
  baseRef: string;
  base: Base;
  files: Files;
  installed: Record<string, string>;
  users: string[];
  user: string;
  env: Record<string, string>;
  cmd: string;
  shellForm: boolean;
  entrypoint: string | null;
  healthcheck: boolean;
  packages: string[];
}

function dockerignore(files: Files): (p: string) => boolean {
  const pats = (files['.dockerignore'] ?? '')
    .split('\n')
    .map((s) => s.trim())
    .filter((s) => s && !s.startsWith('#') && !s.startsWith('!'));
  return (p: string) =>
    pats.some((pat) => {
      const clean = pat.replace(/^\.?\//, '').replace(/^\*\*\//, '').replace(/\/$/, '');
      if (clean.includes('*')) {
        const re = new RegExp('^' + clean.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*') + '(/.*)?$');
        return re.test(p);
      }
      return p === clean || p.startsWith(clean + '/');
    });
}

export interface BuildResult {
  ok: boolean;
  log: string[];
  image?: ImageInfo;
}

export function dockerBuild(files: Files, tag: string, dockerfilePath = 'Dockerfile'): BuildResult {
  const src = files[dockerfilePath];
  const log: string[] = [];
  if (src === undefined) return { ok: false, log: [`ERROR: failed to solve: failed to read dockerfile: open ${dockerfilePath}: no such file or directory`] };
  const { instrs, error } = parseDockerfile(src);
  if (error) return { ok: false, log: [`ERROR: failed to solve: ${error}`] };
  const ignored = dockerignore(files);
  const context: Files = {};
  for (const [p, t] of Object.entries({ ...files, '.git/HEAD': 'ref: refs/heads/main\n' })) if (!ignored(p)) context[p] = t;
  const total = instrs.length;
  log.push(`[+] Building ${(total * 0.4).toFixed(1)}s (${total + 2}/${total + 2}) FINISHED`, ` => [internal] load build definition from ${dockerfilePath}`, ` => [internal] load .dockerignore${files['.dockerignore'] === undefined ? ' (none found)' : ''}`, ` => [internal] load build context: ${(Object.values(context).join('').length / 1024).toFixed(1)}kB transferred`);
  const stages: Stage[] = [];
  let st: Stage | null = null;
  let n = 0;
  for (const i of instrs) {
    n++;
    const label = () => ` => [${st?.name ?? 'stage-' + (stages.length - 1)} ${n}/${total}] ${i.cmd} ${i.args}`;
    if (i.cmd === 'ARG' && !st) continue;
    if (i.cmd === 'FROM') {
      const parts = i.args.split(/\s+/).filter((s) => !s.startsWith('--'));
      const ref = parts[0];
      const alias = parts[1]?.toLowerCase() === 'as' ? parts[2] : null;
      const prev = stages.find((s) => s.name && s.name.toLowerCase() === ref.toLowerCase());
      let next: Stage;
      if (prev) next = { ...prev, files: { ...prev.files }, installed: { ...prev.installed }, env: { ...prev.env }, packages: [...prev.packages], users: [...prev.users], name: alias };
      else {
        const base = lookupBase(ref);
        if (!base) {
          log.push(` => ERROR [internal] load metadata for ${ref}`, `ERROR: failed to solve: ${ref}: failed to resolve source metadata: pull access denied, repository does not exist or may require authorization`);
          return { ok: false, log };
        }
        next = { name: alias, baseRef: ref, base, files: {}, installed: {}, users: [...base.users], user: ref.endsWith(':nonroot') ? 'nonroot' : 'root', env: {}, cmd: '', shellForm: false, entrypoint: base.entrypoint, healthcheck: false, packages: [] };
      }
      stages.push(next);
      st = next;
      log.push(` => [${alias ?? 'stage-' + (stages.length - 1)} ${n}/${total}] FROM ${ref}`);
      continue;
    }
    if (!st) return { ok: false, log: [...log, 'ERROR: failed to solve: no build stage in current context'] };
    const cur: Stage = st;
    switch (i.cmd) {
      case 'ENV':
      case 'ARG': {
        const m = /^(\w+)(?:\s*=\s*|\s+)(.*)$/.exec(i.args);
        if (m) cur.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
        log.push(label());
        break;
      }
      case 'COPY':
      case 'ADD': {
        log.push(label());
        const parts = i.args.split(/\s+/);
        const from = parts.find((p) => p.startsWith('--from='))?.slice(7);
        const srcs = parts.filter((p) => !p.startsWith('--')).slice(0, -1);
        if (from) {
          const s = stages.find((x) => x.name?.toLowerCase() === from.toLowerCase());
          if (!s) {
            log.push(`ERROR: failed to solve: invalid from flag value ${from}`);
            return { ok: false, log };
          }
          Object.assign(cur.files, s.files);
          Object.assign(cur.installed, s.installed);
          break;
        }
        for (const s of srcs) {
          const clean = s.replace(/^\.\//, '').replace(/\/$/, '');
          if (clean === '.' || clean === '*' || clean === '') {
            Object.assign(cur.files, context);
            continue;
          }
          const matched = Object.keys(context).filter((p) => p === clean || p.startsWith(clean + '/'));
          if (!matched.length) {
            log.push(` => ERROR ${label().slice(4)}`, `ERROR: failed to solve: failed to compute cache key: "/${clean}": not found`);
            return { ok: false, log };
          }
          for (const p of matched) cur.files[p] = context[p];
        }
        break;
      }
      case 'RUN': {
        log.push(label());
        const a = i.args;
        if (!cur.base.shell && !a.startsWith('[')) {
          log.push(`ERROR: failed to solve: process "/bin/sh -c ${a}" did not complete successfully: exec: "/bin/sh": stat /bin/sh: no such file or directory`);
          return { ok: false, log };
        }
        for (const part of a.split(/&&|;/).map((s) => s.trim())) {
          const fail = (msg: string, code: number) => log.push(`#${n} 0.312 ${msg}`, `ERROR: failed to solve: process "/bin/sh -c ${a}" did not complete successfully: exit code: ${code}`);
          if (/^apt-get\b/.test(part) && cur.base.pm !== 'apt') {
            fail('/bin/sh: apt-get: not found', 127);
            return { ok: false, log };
          }
          if (/^apk\b/.test(part) && cur.base.pm !== 'apk') {
            fail('/bin/sh: 1: apk: not found', 127);
            return { ok: false, log };
          }
          const inst = /^(?:apt-get|apk)\s+(?:-\S+\s+)*(?:install|add)\s+(.*)$/.exec(part);
          if (inst) inst[1].split(/\s+/).filter((p) => p && !p.startsWith('-')).forEach((p) => cur.packages.push(p.split('=')[0]));
          const user = /^(?:useradd|adduser)\s+(?:-\S+\s+(?:\S+\s+)?)*(\S+)$/.exec(part);
          if (user) cur.users.push(user[1]);
          if (/^npm\s+(ci|install|i)\b/.test(part)) {
            const { pkg, error: perr } = readPkg(cur.files);
            if (!pkg) {
              fail(`npm ERR! enoent Could not read package.json: ${perr}`, 254);
              return { ok: false, log };
            }
            const lock = readLock(cur.files);
            if (/^npm\s+ci/.test(part) && !lock) {
              fail('npm ERR! The `npm ci` command can only install with an existing package-lock.json', 1);
              return { ok: false, log };
            }
            const prodOnly = /--omit=dev|--only=prod|--production/.test(part);
            const r = resolve(prodOnly ? { ...pkg, devDependencies: {} } : pkg, lock);
            if (r.errors.length) {
              fail(r.errors[0], 1);
              return { ok: false, log };
            }
            cur.installed = r.installed;
            log.push(`#${n} 4.211 added ${Object.keys(r.installed).length * 23} packages in 4s`);
          }
        }
        break;
      }
      case 'USER':
        cur.user = i.args.split(':')[0];
        log.push(label());
        break;
      case 'CMD':
        cur.cmd = i.args;
        cur.shellForm = !i.args.startsWith('[');
        break;
      case 'ENTRYPOINT':
        cur.entrypoint = i.args;
        break;
      case 'HEALTHCHECK':
        cur.healthcheck = !/NONE/i.test(i.args);
        break;
      default:
        log.push(label());
    }
  }
  const fin = stages[stages.length - 1];
  const sizeMb = fin.base.size + Object.keys(fin.installed).length * 6 + fin.packages.length * 18;
  log.push(' => exporting to image', ` => => naming to docker.io/library/${tag}`);
  const image: ImageInfo = {
    tag,
    base: fin.baseRef,
    user: fin.user,
    env: fin.env,
    cmd: fin.cmd,
    shellForm: fin.shellForm,
    healthcheck: fin.healthcheck,
    packages: fin.packages,
    hasEnvFile: Object.keys(fin.files).some((p) => p === '.env' || p.endsWith('/.env')),
    hasGitDir: Object.keys(fin.files).some((p) => p.startsWith('.git/')),
    sizeMb,
    files: fin.files,
    installed: fin.installed,
    users: fin.users,
    entrypoint: fin.entrypoint,
    family: fin.base.family,
  };
  return { ok: true, log, image };
}

// ---------- docker run ----------

export function dockerRun(img: ImageInfo): { ok: boolean; log: string[] } {
  if (img.user && !img.users.includes(img.user) && !/^\d+$/.test(img.user)) return { ok: false, log: [`docker: Error response from daemon: unable to find user ${img.user}: no matching entries in passwd file.`] };
  if (img.family === 'distroless' && img.shellForm) return { ok: false, log: ['docker: Error response from daemon: failed to create task: exec: "/bin/sh": stat /bin/sh: no such file or directory: unknown.'] };
  let cmd: string[];
  if (img.cmd.startsWith('[')) {
    try {
      cmd = JSON.parse(img.cmd) as string[];
    } catch {
      return { ok: false, log: ['/bin/sh: 1: [: not found'] };
    }
  } else cmd = img.cmd.split(/\s+/).filter(Boolean);
  if (!cmd.length && !img.entrypoint) return { ok: false, log: ['docker: Error response from daemon: No command specified.'] };
  let script: string | null = null;
  if (img.family === 'distroless') {
    script = cmd[0] ?? null;
    if (script === 'node' || script === 'npm') return { ok: false, log: [`Error: Cannot find module '/app/${script}'`, "  code: 'MODULE_NOT_FOUND'", 'hint: distroless already runs node — use CMD ["src/server.js"]'] };
  } else if (cmd[0] === 'node') script = cmd[1] ?? null;
  else if (cmd[0] === 'npm' && cmd[1] === 'start') {
    if (!img.files['package.json']) return { ok: false, log: ['npm ERR! enoent Could not read package.json'] };
    script = 'src/server.js';
  } else return { ok: false, log: [`/bin/sh: 1: ${cmd[0]}: not found`] };
  if (!script) return { ok: false, log: ['node: missing script argument'] };
  const rel = script.replace(/^\/app\//, '').replace(/^\.\//, '');
  if (!img.files[rel]) return { ok: false, log: [`Error: Cannot find module '/app/${rel}'`, "  code: 'MODULE_NOT_FOUND'", 'hint: was the source copied into the image?'] };
  for (const r of [...img.files[rel].matchAll(/require\(['"]([^./'"][^'"]*)['"]\)/g)].map((m) => m[1]))
    if (!img.installed[r]) return { ok: false, log: [`Error: Cannot find module '${r}'`, `Require stack:`, `- /app/${rel}`] };
  const warn = !img.user || img.user === 'root' || img.user === '0' ? ['(warning) container process is running as uid 0 (root)'] : [];
  return { ok: true, log: [...warn, 'ShopFlow API listening on 3000', 'GET /health 200 2ms'] };
}

// ---------- trivy image ----------

export function imageVulns(img: ImageInfo) {
  const base = lookupBase(img.base);
  const os = [...(base?.vulns ?? [])];
  if (base?.pm === 'apt') for (const p of img.packages) if (APT_PKG_VULNS[p]) os.push(APT_PKG_VULNS[p]);
  const secrets: string[] = [];
  if (img.hasEnvFile) secrets.push('/app/.env');
  for (const [k, v] of Object.entries(img.env)) if (/(PASSWORD|SECRET|TOKEN|KEY)/i.test(k) && v && !v.startsWith('$')) secrets.push(`ENV ${k}`);
  return { os, extraLow: base?.extraLow ?? 0, app: auditInstalled(img.installed), secrets };
}

export function imageFindings(img: ImageInfo): Finding[] {
  const v = imageVulns(img);
  const out: Finding[] = v.os.map((o) => ({ tool: 'trivy-image' as const, ruleId: o.id, severity: o.severity, title: o.title, pkg: o.pkg, installed: o.installed, fixed: o.fixed || '(no fix yet)', file: `${img.tag} (os)`, remediation: o.fixed ? `Rebuild on a patched or smaller base, or upgrade ${o.pkg} to ${o.fixed}.` : 'No fix available: choose a minimal base or document an accepted risk (--ignore-unfixed).' }));
  for (const h of v.app) out.push({ tool: 'trivy-image', ruleId: h.adv.id, severity: h.adv.severity, title: h.adv.title, pkg: h.adv.pkg, installed: h.installed, fixed: h.adv.fixed, file: `${img.tag} (node-pkg)`, remediation: `Upgrade ${h.adv.pkg} to ${h.adv.fixed}.` });
  for (const s of v.secrets) out.push({ tool: 'trivy-image', ruleId: 'secret', severity: 'CRITICAL', title: `Secret found in image: ${s}`, file: img.tag, remediation: 'Add .env to .dockerignore and never put secrets in ENV/ARG; inject them at runtime.' });
  return out;
}
