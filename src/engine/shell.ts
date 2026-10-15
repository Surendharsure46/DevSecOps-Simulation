import type { CmdResult, Files, Finding, LabState, ToolName } from './types';
import { argv, boxTable, C, clock, cmpVer, diffLines, hexDigest, sevColor } from './util';
import { addPaths, ancestry, commitIndex, filterRepoInvertPaths, filterRepoReplace, headCommit, isAncestor, status } from './git';
import { leakToFinding, scanFiles, scanHistory, type Leak } from './secrets';
import { runSast, sastToFinding } from './sast';
import { auditInstalled, latest, lockInSync, readLock, readPkg, REGISTRY, resolve, sbomCycloneDx, vulnToFinding, writeLock, type PkgJson } from './sca';
import { dockerBuild, dockerRun, hadolint, hadolintSeverity, imageFindings, imageVulns, trivyConfigDockerfile } from './container';
import { checkov, checkToFinding } from './iac';
import { resourcesOf } from './hcl';
import { denyMessage, httpRequest, kyverno, kyvernoFindings, parseWorkloads, rollout, STAGING_HOST, zapAlerts, zapToFinding, type RunningApp } from './staging';

export interface TestCase {
  suite: string;
  name: string;
  run: (fs: Files, installed: Record<string, string>) => string | null;
}

export interface ShellCtx {
  s: LabState;
  fs: Files;
  installed: Record<string, string>;
  pipeline: boolean;
  env: Record<string, string>;
  flags: Record<string, string | number | boolean>;
  tests: TestCase[];
  /** commit id used for history-based scans */
  commit: string;
}

export const REPO_URL = 'https://git.shopflow.local/shopflow/shopflow-api.git';

export function revOf(s: LabState): string {
  return hexDigest(JSON.stringify(s.files) + '|' + s.head + '|' + JSON.stringify(s.installed), 12);
}

function record(ctx: ShellCtx, tool: ToolName, findings: Finding[], target: string) {
  if (!ctx.pipeline) ctx.s.scans[tool] = { tool, rev: revOf(ctx.s), findings, at: Date.now(), target };
}

const res = (out: string[], code = 0): CmdResult => ({ out, code });
const strip = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, '');
const flag = (args: string[], ...names: string[]) => args.some((a) => names.includes(a) || names.some((n) => a.startsWith(n + '=')));

function opt(args: string[], ...names: string[]): string | null {
  for (let i = 0; i < args.length; i++)
    for (const n of names) {
      if (args[i] === n && i + 1 < args.length) return args[i + 1];
      if (args[i].startsWith(n + '=')) return args[i].slice(n.length + 1);
    }
  return null;
}

function positional(args: string[], withValue: string[] = []): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith('-')) {
      if (withValue.includes(args[i])) i++;
      continue;
    }
    out.push(args[i]);
  }
  return out;
}

const norm = (p: string) => p.replace(/^\.\//, '').replace(/^\/workspace\/shopflow-api\//, '').replace(/^\/app\//, '');

function listDir(fs: Files, dir: string): string[] {
  const d = norm(dir).replace(/^\.$/, '').replace(/\/$/, '');
  const names = new Set<string>();
  for (const p of Object.keys(fs)) {
    if (d && !p.startsWith(d + '/')) continue;
    const rest = d ? p.slice(d.length + 1) : p;
    names.add(rest.includes('/') ? rest.split('/')[0] + '/' : rest);
  }
  return [...names].sort((a, b) => (a.endsWith('/') === b.endsWith('/') ? a.localeCompare(b) : a.endsWith('/') ? -1 : 1));
}

// ---------------------------------------------------------------------------

export function runLine(line: string, ctx: ShellCtx): CmdResult {
  const expanded = line.replace(/\$\{(\w+)\}|\$(\w+)/g, (_m, a, b) => ctx.env[a ?? b] ?? '');
  const parts: { cmd: string; op: string }[] = [];
  let cur = '';
  let q: string | null = null;
  for (let i = 0; i < expanded.length; i++) {
    const c = expanded[i];
    if (q) {
      if (c === q) q = null;
      cur += c;
      continue;
    }
    if (c === '"' || c === "'") {
      q = c;
      cur += c;
      continue;
    }
    const two = expanded.slice(i, i + 2);
    if (two === '&&' || two === '||') {
      parts.push({ cmd: cur, op: two });
      cur = '';
      i++;
    } else if (c === ';') {
      parts.push({ cmd: cur, op: ';' });
      cur = '';
    } else cur += c;
  }
  parts.push({ cmd: cur, op: '' });
  const out: string[] = [];
  let code = 0;
  let prevOp = '';
  for (const p of parts) {
    const skip = (prevOp === '&&' && code !== 0) || (prevOp === '||' && code === 0);
    prevOp = p.op || prevOp;
    if (skip || !p.cmd.trim()) continue;
    const r = runPiped(p.cmd.trim(), ctx);
    out.push(...r.out);
    code = r.code;
  }
  return { out, code };
}

function runPiped(cmd: string, ctx: ShellCtx): CmdResult {
  let redirect: { file: string; append: boolean } | null = null;
  cmd = cmd.replace(/\s2>&1/g, '').replace(/\s2>\/dev\/null/g, '');
  const rm = /\s(>>?)\s*([^\s>|]+)\s*$/.exec(cmd);
  if (rm) {
    redirect = { file: norm(rm[2]), append: rm[1] === '>>' };
    cmd = cmd.slice(0, rm.index);
  }
  const segs: string[] = [];
  let cur = '';
  let q: string | null = null;
  for (const c of cmd) {
    if (q) {
      if (c === q) q = null;
      cur += c;
    } else if (c === '"' || c === "'") {
      q = c;
      cur += c;
    } else if (c === '|') {
      segs.push(cur.trim());
      cur = '';
    } else cur += c;
  }
  segs.push(cur.trim());
  let r = runSimple(segs[0], ctx, null);
  for (const s of segs.slice(1)) r = runSimple(s, ctx, r.out.map(strip));
  if (redirect) {
    const text = r.out.map(strip).join('\n') + (r.out.length ? '\n' : '');
    ctx.fs[redirect.file] = redirect.append ? (ctx.fs[redirect.file] ?? '') + text : text;
    return { out: [], code: r.code };
  }
  return r;
}

function runSimple(cmd: string, ctx: ShellCtx, stdin: string[] | null): CmdResult {
  const a = argv(cmd);
  while (a.length > 1 && /^\w+=/.test(a[0])) a.shift();
  if (!a.length) return res([]);
  const [c, ...args] = a;
  try {
    switch (c) {
      case 'help':
        return help();
      case 'clear':
        return res(['\x1bc']);
      case 'pwd':
        return res(['/workspace/shopflow-api']);
      case 'whoami':
        return res([ctx.pipeline ? 'runner' : 'devsecops']);
      case 'date':
        return res([new Date().toUTCString()]);
      case 'cd':
        return !args.length || ['.', '~', '/workspace/shopflow-api'].includes(args[0]) ? res([]) : res(['cd: this lab shell stays at the repository root — use paths like src/config/storage.js'], 1);
      case 'node':
        return args[0] === '-v' || args[0] === '--version' ? res(['v20.18.0']) : res([C.gray('(servers are not started in this shell — use docker run, or deploy through the pipeline)')]);
      case 'export':
        for (const kv of args) {
          const m = /^(\w+)=(.*)$/.exec(kv);
          if (m) ctx.env[m[1]] = m[2];
        }
        return res([]);
      case 'env':
      case 'printenv':
        return res(Object.entries(ctx.env).map(([k, v]) => `${k}=${v}`));
      case 'echo':
        return res([args.filter((x) => x !== '-e' && x !== '-n').join(' ').replace(/\\n/g, '\n')].flatMap((x) => x.split('\n')));
      case 'printf':
        return res((args[0] ?? '').replace(/\\n$/, '').split('\\n'));
      case 'ls': {
        const dir = positional(args)[0] ?? '';
        if (norm(dir) in ctx.fs) return res([norm(dir)]);
        const entries = listDir(ctx.fs, dir).filter((n) => flag(args, '-a', '-la', '-al', '-A') || !n.startsWith('.'));
        if (!entries.length && dir) return res([`ls: cannot access '${dir}': No such file or directory`], 2);
        return res(entries.map((e) => (e.endsWith('/') ? C.blue(e) : e)));
      }
      case 'tree':
        return res(['.', ...Object.keys(ctx.fs).sort().map((p) => '├── ' + p)]);
      case 'cat': {
        const out: string[] = [];
        let code = 0;
        for (const f of positional(args)) {
          const p = norm(f);
          if (p in ctx.fs) out.push(...ctx.fs[p].replace(/\n$/, '').split('\n'));
          else {
            out.push(`cat: ${f}: ${listDir(ctx.fs, p).length ? 'Is a directory' : 'No such file or directory'}`);
            code = 1;
          }
        }
        return res(out, code);
      }
      case 'head':
      case 'tail': {
        const n = Number(opt(args, '-n') ?? 10);
        const f = positional(args, ['-n'])[0];
        const lines = stdin ?? (f ? (ctx.fs[norm(f)] ?? '').split('\n') : []);
        return res(c === 'head' ? lines.slice(0, n) : lines.slice(-n));
      }
      case 'wc':
        return res([String((stdin ?? (ctx.fs[norm(args[args.length - 1] ?? '')] ?? '').split('\n')).length)]);
      case 'grep':
        return grep(args, ctx, stdin);
      case 'touch':
        for (const f of args) if (!(norm(f) in ctx.fs)) ctx.fs[norm(f)] = '';
        return res([]);
      case 'mkdir':
        return res([]);
      case 'rm': {
        for (const f of positional(args)) {
          const p = norm(f).replace(/\/$/, '');
          if (p in ctx.fs) delete ctx.fs[p];
          else if (flag(args, '-r', '-rf', '-fr') && Object.keys(ctx.fs).some((x) => x.startsWith(p + '/'))) Object.keys(ctx.fs).filter((x) => x.startsWith(p + '/')).forEach((x) => delete ctx.fs[x]);
          else if (!flag(args, '-f', '-rf', '-fr')) return res([`rm: cannot remove '${f}': No such file or directory`], 1);
        }
        return res([]);
      }
      case 'cp':
      case 'mv': {
        const [src, dst] = positional(args).map(norm);
        if (!(src in ctx.fs)) return res([`${c}: cannot stat '${src}': No such file or directory`], 1);
        ctx.fs[dst] = ctx.fs[src];
        if (c === 'mv') delete ctx.fs[src];
        return res([]);
      }
      case 'true':
        return res([]);
      case 'false':
        return res([], 1);
      case 'exit':
        return res([], Number(args[0] ?? 0));
      case 'sleep':
        return res([]);
      case 'git':
        return git(args, ctx);
      case 'npm':
        return npm(args, ctx);
      case 'npx':
      case 'jest':
        return npm(['test'], ctx);
      case 'gitleaks':
        return gitleaks(args, ctx);
      case 'semgrep':
        return semgrep(args, ctx);
      case 'trivy':
        return trivy(args, ctx);
      case 'syft':
        return syft(args, ctx);
      case 'hadolint':
        return hadolintCmd(args, ctx);
      case 'docker':
        return docker(args, ctx);
      case 'checkov':
        return checkovCmd(args, ctx);
      case 'terraform':
        return terraform(args, ctx);
      case 'kubectl':
        return kubectl(args, ctx);
      case 'kyverno':
        return kyvernoCmd(args, ctx);
      case 'aws':
        return aws(args, ctx);
      case 'curl':
        return curl(args, ctx);
      case 'zap-baseline.py':
      case 'zap-full-scan.py':
        return zap(c, args, ctx);
      default:
        return res([`bash: ${c}: command not found`, C.gray("Type 'help' to list the tools available in this lab.")], 127);
    }
  } catch (e) {
    return res([C.red(`internal error: ${(e as Error).message}`)], 1);
  }
}

function help(): CmdResult {
  return res([
    C.bold('ShopFlow DevSecOps workstation') + C.gray('  (repo: /workspace/shopflow-api)'),
    '',
    C.cyan('Files    ') + 'ls, cat, head, tail, grep -rn, echo … > file, touch, rm, cp, mv, tree',
    C.cyan('Git      ') + 'git status | add | commit -m | log [-p] | diff [--staged] | show | push [--force] | remote | restore | filter-repo',
    C.cyan('Node     ') + 'npm install [pkg@ver] | ci | test | audit [fix] | update | view <pkg> versions | outdated',
    C.cyan('Secrets  ') + 'gitleaks git -v · gitleaks dir . · gitleaks detect [--no-git]',
    C.cyan('SAST     ') + 'semgrep scan --config auto [--error]',
    C.cyan('SCA/SBOM ') + 'trivy fs . [--severity HIGH,CRITICAL] [--exit-code 1] · syft . -o cyclonedx-json=sbom.cdx.json',
    C.cyan('Container') + ' hadolint Dockerfile · trivy config . · docker build -t name:tag . · docker run · docker push · trivy image',
    C.cyan('IaC      ') + 'terraform init | validate | plan · checkov -d infra',
    C.cyan('K8s      ') + 'kubectl apply -f k8s/ | get pods | set image · kyverno apply policies/ --resource <file>',
    C.cyan('Cloud    ') + 'aws iam list-access-keys | update-access-key | delete-access-key | create-access-key · aws cloudtrail lookup-events',
    C.cyan('DAST     ') + `curl -i https://${STAGING_HOST}/health · zap-baseline.py -t URL · zap-full-scan.py -t URL`,
    '',
    C.gray('Supports pipes (| grep, | head), redirects (>, >>), &&, || and ;. Tab completes file names; ↑/↓ recall history.'),
  ]);
}

function grep(args: string[], ctx: ShellCtx, stdin: string[] | null): CmdResult {
  const pos = positional(args, ['-e']);
  const pattern = opt(args, '-e') ?? pos.shift();
  if (!pattern) return res(['usage: grep [-rniEFv] PATTERN [FILE...]'], 2);
  const flags = args.filter((x) => /^-[a-zA-Z]+$/.test(x)).join('');
  let re: RegExp;
  try {
    re = new RegExp(flags.includes('F') ? pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') : pattern, flags.includes('i') ? 'i' : '');
  } catch {
    return res([`grep: invalid regular expression: ${pattern}`], 2);
  }
  const invert = flags.includes('v');
  const out: string[] = [];
  if (stdin && !pos.length) {
    stdin.forEach((l) => re.test(l) !== invert && out.push(l));
    return res(out, out.length ? 0 : 1);
  }
  const recursive = /[rR]/.test(flags);
  const targets = pos.length ? pos.map(norm) : recursive ? ['.'] : [];
  const files = Object.keys(ctx.fs).filter((p) => targets.some((t) => t === '.' || t === '' || p === t || (recursive && p.startsWith(t.replace(/\/$/, '') + '/'))));
  const multi = files.length > 1 || recursive;
  for (const f of files.sort())
    ctx.fs[f].split('\n').forEach((l, i) => {
      if (re.test(l) !== invert) out.push(`${multi ? C.magenta(f) + C.cyan(':') : ''}${flags.includes('n') ? C.green(String(i + 1)) + C.cyan(':') : ''}${l}`);
    });
  return res(out, out.length ? 0 : 1);
}

// ---------------------------------------------------------------------------
// git

function colorDiff(l: string): string {
  if (l.startsWith('+')) return C.green(l);
  if (l.startsWith('-')) return C.red(l);
  if (l.startsWith('@@')) return C.cyan(l);
  return l;
}

function commitDiff(s: LabState, id: string): string[] {
  const c = s.commits.find((x) => x.id === id)!;
  const parent = s.commits.find((x) => x.id === c.parent);
  const out: string[] = [];
  for (const p of Object.keys({ ...c.files, ...(parent?.files ?? {}) }).sort()) {
    if (parent?.files[p] === c.files[p]) continue;
    out.push(C.bold(`diff --git a/${p} b/${p}`), ...diffLines(parent?.files[p] ?? '', c.files[p] ?? '').map(colorDiff), '');
  }
  return out;
}

function git(args: string[], ctx: ShellCtx): CmdResult {
  const s = ctx.s;
  const [sub, ...rest] = args;
  if (ctx.pipeline && !['rev-parse', 'log', 'status', 'diff', 'show'].includes(sub)) return res([`git ${sub}: not permitted on the CI runner`], 1);
  switch (sub) {
    case 'status': {
      const st = status(s);
      const out = ['On branch main', s.remote.head === s.head ? "Your branch is up to date with 'origin/main'." : s.remote.url ? "Your branch is ahead of 'origin/main' (use \"git push\" to publish your local commits)." : 'No upstream: remote "origin" is not configured.', ''];
      const name = (x: string) => ({ A: 'new file:   ', M: 'modified:   ', D: 'deleted:    ' })[x] ?? '';
      const staged = st.filter((e) => e.staged);
      const unstaged = st.filter((e) => e.unstaged);
      const untracked = st.filter((e) => e.untracked);
      if (staged.length) out.push('Changes to be committed:', ...staged.map((e) => '\t' + C.green(name(e.staged!) + e.path)), '');
      if (unstaged.length) out.push('Changes not staged for commit:', '  (use "git add <file>..." to update what will be committed)', ...unstaged.map((e) => '\t' + C.red(name(e.unstaged!) + e.path)), '');
      if (untracked.length) out.push('Untracked files:', '  (use "git add <file>..." to include in what will be committed)', ...untracked.map((e) => '\t' + C.red(e.path)), '');
      if (!st.length) out.push('nothing to commit, working tree clean');
      return res(out);
    }
    case 'add': {
      if (!rest.length) return res(['Nothing specified, nothing added.', "hint: Maybe you wanted to say 'git add .'?"]);
      const errs = addPaths(s, rest);
      return res(errs.flatMap((e) => e.split('\n')), errs.some((e) => e.startsWith('fatal')) ? 128 : 0);
    }
    case 'commit': {
      const msg = opt(rest, '-m', '--message') ?? opt(rest, '-am');
      if (flag(rest, '-a', '-am', '--all'))
        for (const p of Object.keys(s.index)) {
          if (p in s.files) s.index[p] = s.files[p];
          else delete s.index[p];
        }
      if (!msg) return res(['error: please supply a commit message with -m "message" (no editor in this lab)'], 1);
      const c = commitIndex(s, msg);
      if (!c) return res(['On branch main', status(s).length ? 'no changes added to commit (use "git add" and/or "git commit -a")' : 'nothing to commit, working tree clean'], 1);
      const parent = s.commits.find((x) => x.id === c.parent);
      const changed = Object.keys({ ...c.files, ...(parent?.files ?? {}) }).filter((p) => c.files[p] !== parent?.files[p]);
      return res([`[main ${c.id.slice(0, 7)}] ${msg}`, ` ${changed.length} file${changed.length === 1 ? '' : 's'} changed`]);
    }
    case 'log': {
      const patch = flag(rest, '-p', '--patch');
      if (patch && !ctx.pipeline) ctx.flags.inspectedHistory = true;
      const all = ancestry(s.commits, ctx.pipeline ? ctx.commit : s.head);
      const n = Number(opt(rest, '-n') ?? rest.find((x) => /^-\d+$/.test(x))?.slice(1) ?? all.length);
      const list = all.slice(0, n);
      if (flag(rest, '--oneline'))
        return res(list.map((c, i) => `${C.yellow(c.id.slice(0, 7))} ${i === 0 ? C.cyan('(HEAD -> main' + (s.remote.head === c.id ? ', origin/main' : '') + ') ') : s.remote.head === c.id ? C.cyan('(origin/main) ') : ''}${c.message}`));
      const out: string[] = [];
      for (const c of list) {
        out.push(C.yellow(`commit ${c.id}`), `Author: ${c.author}`, `Date:   ${new Date(c.date).toUTCString()}`, '', `    ${c.message}`, '');
        if (patch) out.push(...commitDiff(s, c.id));
      }
      return res(out);
    }
    case 'show': {
      if (!ctx.pipeline) ctx.flags.inspectedHistory = true;
      const [r, path] = (rest[0] ?? 'HEAD').split(':');
      const c = r === 'HEAD' ? headCommit(s) : s.commits.find((x) => x.id.startsWith(r));
      if (!c) return res([`fatal: ambiguous argument '${rest[0]}': unknown revision`], 128);
      if (path !== undefined) return c.files[path] !== undefined ? res(c.files[path].split('\n')) : res([`fatal: path '${path}' does not exist in '${r}'`], 128);
      return res([C.yellow(`commit ${c.id}`), `Author: ${c.author}`, `Date:   ${new Date(c.date).toUTCString()}`, '', `    ${c.message}`, '', ...commitDiff(s, c.id)]);
    }
    case 'diff': {
      const staged = flag(rest, '--staged', '--cached');
      const from = staged ? (headCommit(s)?.files ?? {}) : s.index;
      const to = staged ? s.index : s.files;
      const only = positional(rest).map(norm);
      const out: string[] = [];
      const keys = staged ? Object.keys({ ...from, ...to }) : Object.keys(s.index);
      for (const p of keys.sort()) {
        if ((only.length && !only.includes(p)) || from[p] === to[p]) continue;
        out.push(C.bold(`diff --git a/${p} b/${p}`), ...diffLines(from[p] ?? '', to[p] ?? '').map(colorDiff));
      }
      return res(out);
    }
    case 'restore':
    case 'checkout': {
      const paths = positional(rest).filter((x) => x !== '--').map(norm);
      if (flag(rest, '--staged')) {
        const head = headCommit(s)?.files ?? {};
        for (const p of paths) {
          if (p in head) s.index[p] = head[p];
          else delete s.index[p];
        }
        return res([]);
      }
      for (const p of paths) {
        if (!(p in s.index)) return res([`error: pathspec '${p}' did not match any file(s) known to git`], 1);
        s.files[p] = s.index[p];
      }
      return res([]);
    }
    case 'reset': {
      const head = headCommit(s);
      if (flag(rest, '--hard') && head) {
        for (const p of Object.keys(s.index)) delete s.files[p];
        Object.assign(s.files, head.files);
        s.index = { ...head.files };
        return res([`HEAD is now at ${s.head.slice(0, 7)} ${head.message}`]);
      }
      s.index = { ...(head?.files ?? {}) };
      return res(['Unstaged changes after reset.']);
    }
    case 'rev-parse':
      return res([ctx.pipeline ? ctx.commit : s.head]);
    case 'remote': {
      if (rest[0] === 'add') {
        if (s.remote.url) return res(['error: remote origin already exists.'], 3);
        s.remote.url = rest[2] ?? null;
        return res([]);
      }
      if (rest[0] === 'remove' || rest[0] === 'rm') {
        s.remote.url = null;
        return res([]);
      }
      return res(s.remote.url ? (flag(rest, '-v') ? [`origin\t${s.remote.url} (fetch)`, `origin\t${s.remote.url} (push)`] : ['origin']) : []);
    }
    case 'push': {
      if (!s.remote.url) return res(["fatal: 'origin' does not appear to be a git repository", 'fatal: Could not read from remote repository.'], 128);
      if (s.remote.head === s.head) return res(['Everything up-to-date']);
      const force = flag(rest, '--force', '-f', '--force-with-lease');
      if (s.remote.head && !isAncestor(s.commits, s.remote.head, s.head) && !force)
        return res([`To ${s.remote.url}`, C.red(' ! [rejected]        main -> main (non-fast-forward)'), `error: failed to push some refs to '${s.remote.url}'`, "hint: Updates were rejected because the remote contains work you do not have locally.", "hint: If you rewrote history on purpose, use 'git push --force'."], 1);
      const old = s.remote.head;
      s.remote.head = s.head;
      s.remote.commits = ancestry(s.commits, s.head);
      ctx.flags.pushRequested = s.head;
      const forced = force && old && !isAncestor(s.commits, old, s.head);
      return res(['Writing objects: 100% (7/7), 1.2 KiB | 1.2 MiB/s, done.', `To ${s.remote.url}`, `${forced ? ' + ' : '   '}${(old ?? '0000000').slice(0, 7)}${forced ? '...' : '..'}${s.head.slice(0, 7)}  main -> main${forced ? ' (forced update)' : ''}`, C.gray('remote: CI pipeline triggered → see the Pipeline tab')]);
    }
    case 'filter-repo':
      return filterRepo(rest, ctx);
    default:
      return res([`git: '${sub ?? ''}' is not supported in this lab. Try: status, add, commit, log, show, diff, push, remote, restore, reset, filter-repo`], 1);
  }
}

function filterRepo(args: string[], ctx: ShellCtx): CmdResult {
  const s = ctx.s;
  if (!flag(args, '--force') && s.remote.url)
    return res(['Aborting: Refusing to destructively overwrite repo history since', 'this does not look like a fresh clone.', 'Please operate on a fresh clone instead.  If you want to proceed', 'anyway, use --force.'], 1);
  const dirty = status(s).filter((e) => !e.untracked);
  if (dirty.length) return res(['Aborting: You have uncommitted changes. Commit or stash them first:', ...dirty.map((e) => '  ' + e.path)], 1);
  const replace = opt(args, '--replace-text');
  let n: number;
  if (replace) {
    const src = ctx.fs[norm(replace)];
    if (src === undefined) return res([`Error: --replace-text file '${replace}' not found`], 1);
    const rules = src
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'))
      .map((l) => {
        const [from, to] = l.split('==>');
        return from.startsWith('regex:') ? { from: new RegExp(from.slice(6), 'g'), to: to ?? '***REMOVED***' } : { from: from.replace(/^literal:/, ''), to: to ?? '***REMOVED***' };
      });
    n = filterRepoReplace(s, rules);
  } else if (flag(args, '--invert-paths')) {
    const paths = args.flatMap((x, i) => (x === '--path' && args[i + 1] ? [norm(args[i + 1])] : []));
    if (!paths.length) return res(['Error: --invert-paths needs at least one --path'], 1);
    n = filterRepoInvertPaths(s, paths);
  } else return res(['usage: git filter-repo (--replace-text <file> | --invert-paths --path <path>) [--force]'], 1);
  const hadRemote = !!s.remote.url;
  s.remote.url = null;
  return res([
    `Parsed ${ancestry(s.commits, s.head).length} commits`,
    'New history written; now repacking/cleaning...',
    `HEAD is now at ${s.head.slice(0, 7)} ${headCommit(s)?.message ?? ''}`,
    `Completely finished. (${n} commit(s) rewritten)`,
    ...(hadRemote ? [C.yellow("NOTICE: Removing 'origin' remote; see 'Why is my origin removed?' in the manual if you want to push back there."), C.yellow(`        (was ${REPO_URL})`)] : []),
  ]);
}

// ---------------------------------------------------------------------------
// npm

function setInstalled(ctx: ShellCtx, next: Record<string, string>) {
  for (const k of Object.keys(ctx.installed)) delete ctx.installed[k];
  Object.assign(ctx.installed, next);
}

const sevNames: Record<string, string> = { LOW: 'low', MEDIUM: 'moderate', HIGH: 'high', CRITICAL: 'critical' };

function sevSummary(sevs: string[]): string {
  return ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    .map((s) => [s, sevs.filter((x) => x === s).length] as const)
    .filter(([, n]) => n)
    .map(([s, n]) => `${n} ${sevNames[s]}`)
    .join(', ');
}

function savePkg(ctx: ShellCtx, pkg: PkgJson) {
  ctx.fs['package.json'] = JSON.stringify(pkg, null, 2) + '\n';
}

function npm(args: string[], ctx: ShellCtx): CmdResult {
  const [sub, ...rest] = args;
  if (sub === '-v' || sub === '--version') return res(['10.8.2']);
  const { pkg, error } = readPkg(ctx.fs);
  if (!pkg && sub !== 'view') return res([`npm ERR! code ${error?.startsWith('ENOENT') ? 'ENOENT' : 'EJSONPARSE'}`, `npm ERR! ${error}`], 1);
  const p = pkg!;
  switch (sub) {
    case 'install':
    case 'i':
    case 'add': {
      const names = positional(rest);
      for (const n of names) {
        const at = n.lastIndexOf('@');
        const name = at > 0 ? n.slice(0, at) : n;
        const ver = at > 0 ? n.slice(at + 1) : 'latest';
        const versions = REGISTRY[name];
        if (!versions) return res([`npm ERR! code E404`, `npm ERR! 404 Not Found - GET https://registry.npmjs.org/${name} - Not found`], 1);
        const resolved = ver === 'latest' ? latest(name)! : versions.includes(ver) ? ver : null;
        if (!resolved) return res([`npm ERR! code ETARGET`, `npm ERR! notarget No matching version found for ${name}@${ver}.`, C.gray(`  available: ${versions.join(', ')}`)], 1);
        const dev = flag(rest, '-D', '--save-dev') || (!!p.devDependencies?.[name] && !p.dependencies?.[name]);
        const target = dev ? (p.devDependencies ??= {}) : (p.dependencies ??= {});
        target[name] = '^' + resolved;
        ctx.installed[name] = resolved;
      }
      if (names.length) savePkg(ctx, p);
      const r = resolve(p, { ...(readLock(ctx.fs) ?? {}), ...ctx.installed });
      if (r.errors.length) return res(r.errors.join('\n').split('\n'), 1);
      const before = { ...ctx.installed };
      setInstalled(ctx, r.installed);
      ctx.fs['package-lock.json'] = writeLock(p, r.installed);
      const changed = Object.keys(r.installed).filter((k) => before[k] !== r.installed[k]).length + names.length;
      const vulns = auditInstalled(r.installed);
      const out = [`${changed ? `changed ${changed} package${changed > 1 ? 's' : ''}, ` : 'up to date, '}audited ${Object.keys(r.installed).length * 23 + 1} packages in 2s`, ''];
      out.push(vulns.length ? `${vulns.length} vulnerabilit${vulns.length > 1 ? 'ies' : 'y'} (${sevSummary(vulns.map((v) => v.adv.severity))})` : 'found 0 vulnerabilities');
      if (vulns.length) out.push('', 'Run `npm audit` for details.');
      return res(out);
    }
    case 'uninstall':
    case 'remove':
    case 'rm':
      for (const n of positional(rest)) {
        delete p.dependencies?.[n];
        delete p.devDependencies?.[n];
        delete ctx.installed[n];
      }
      savePkg(ctx, p);
      ctx.fs['package-lock.json'] = writeLock(p, ctx.installed);
      return res([`removed ${positional(rest).length} package(s)`]);
    case 'update':
    case 'up': {
      const r = resolve(p, null);
      if (r.errors.length) return res(r.errors.join('\n').split('\n'), 1);
      const changed = Object.keys(r.installed).filter((k) => ctx.installed[k] !== r.installed[k]);
      setInstalled(ctx, r.installed);
      ctx.fs['package-lock.json'] = writeLock(p, r.installed);
      return res([`changed ${changed.length} package(s)`, ...changed.map((k) => C.gray(`  ${k} → ${r.installed[k]}`))]);
    }
    case 'ci': {
      const lock = readLock(ctx.fs);
      if (!lock) return res(['npm ERR! code EUSAGE', 'npm ERR! The `npm ci` command can only install with an existing package-lock.json.'], 1);
      const problems = lockInSync(p, lock);
      if (problems.length) return res(['npm ERR! code EUSAGE', 'npm ERR! `npm ci` can only install packages when your package.json and package-lock.json are in sync.', 'npm ERR! Please update your lock file with `npm install` before continuing.', ...problems.map((x) => 'npm ERR! ' + x)], 1);
      const prod = flag(rest, '--omit=dev', '--production');
      setInstalled(ctx, Object.fromEntries(Object.entries(lock).filter(([n]) => !prod || !(n in (p.devDependencies ?? {})))));
      return res([`added ${Object.keys(ctx.installed).length * 23} packages in 3s`]);
    }
    case 'test':
    case 't':
      return runTests(ctx, p);
    case 'run':
      return rest[0] === 'test' ? runTests(ctx, p) : res([`npm ERR! Missing script: "${rest[0] ?? ''}"`], 1);
    case 'start':
      return res([C.gray('(servers are not started in this shell — use docker run or deploy through the pipeline)')]);
    case 'audit': {
      if (rest[0] === 'fix') return auditFix(ctx, p, flag(rest, '--force'));
      const level = opt(rest, '--audit-level') ?? 'low';
      const vulns = auditInstalled(ctx.installed);
      record(ctx, 'npm-audit', vulns.map((v) => ({ ...vulnToFinding(v), tool: 'npm-audit' as const })), 'package-lock.json');
      if (!vulns.length) return res(['found 0 vulnerabilities']);
      const out = ['# npm audit report', ''];
      for (const name of [...new Set(vulns.map((v) => v.adv.pkg))]) {
        const vs = vulns.filter((v) => v.adv.pkg === name);
        out.push(C.bold(`${name}  ${vs[0].adv.vulnerable}`), ...vs.map((v) => `Severity: ${sevColor(v.adv.severity, sevNames[v.adv.severity])}  ${v.adv.title} - https://github.com/advisories/${v.adv.ghsa}`));
        const need = vs.map((v) => v.adv.fixed).sort(cmpVer).pop()!;
        out.push(need.split('.')[0] !== ctx.installed[name].split('.')[0] ? `fix available via \`npm audit fix --force\`\nWill install ${name}@${need}, which is a breaking change` : 'fix available via `npm audit fix`', `node_modules/${name}`, '');
      }
      out.push(`${vulns.length} vulnerabilities (${sevSummary(vulns.map((v) => v.adv.severity))})`);
      const order = ['low', 'moderate', 'high', 'critical'];
      return res(out.join('\n').split('\n'), vulns.some((v) => order.indexOf(sevNames[v.adv.severity]) >= order.indexOf(level)) ? 1 : 0);
    }
    case 'view':
    case 'info': {
      const name = rest[0]?.split('@')[0];
      const versions = name ? REGISTRY[name] : undefined;
      if (!versions) return res([`npm ERR! 404 '${rest[0] ?? ''}' is not in this registry.`], 1);
      if (rest[1] === 'versions') return res([`[ ${versions.map((v) => `'${v}'`).join(', ')} ]`]);
      return res([C.bold(`${name}@${latest(name!)}`) + ` | versions: ${versions.join(', ')}`]);
    }
    case 'outdated': {
      const rows = Object.entries(ctx.installed).filter(([n, v]) => latest(n) && cmpVer(latest(n)!, v) > 0);
      return res(rows.length ? ['Package        Current  Latest', ...rows.map(([n, v]) => `${n.padEnd(15)}${v.padEnd(9)}${latest(n)}`)] : [], rows.length ? 1 : 0);
    }
    default:
      return res([`Unknown command: "${sub ?? ''}"`], 1);
  }
}

function auditFix(ctx: ShellCtx, pkg: PkgJson, force: boolean): CmdResult {
  const vulns = auditInstalled(ctx.installed);
  const skipped: string[] = [];
  let changed = 0;
  for (const name of [...new Set(vulns.map((v) => v.adv.pkg))]) {
    const need = vulns.filter((v) => v.adv.pkg === name).map((v) => v.adv.fixed).sort(cmpVer).pop()!;
    const cur = ctx.installed[name];
    const sameMajor = need.split('.')[0] === cur.split('.')[0];
    let target: string | undefined;
    if (sameMajor || force) target = REGISTRY[name].filter((v) => cmpVer(v, need) >= 0 && (force || v.split('.')[0] === cur.split('.')[0])).sort(cmpVer).pop();
    else {
      // fix what is possible without a breaking change, report the rest
      skipped.push(`${name}@${need}`);
      target = REGISTRY[name].filter((v) => v.split('.')[0] === cur.split('.')[0] && cmpVer(v, cur) > 0).sort(cmpVer).pop();
      if (target && auditInstalled({ [name]: target }).length >= auditInstalled({ [name]: cur }).length) target = undefined;
    }
    if (!target) continue;
    const dep = pkg.dependencies?.[name] !== undefined ? pkg.dependencies : pkg.devDependencies;
    if (dep) dep[name] = '^' + target;
    ctx.installed[name] = target;
    changed++;
  }
  savePkg(ctx, pkg);
  ctx.fs['package-lock.json'] = writeLock(pkg, ctx.installed);
  const left = auditInstalled(ctx.installed);
  const out = [`changed ${changed} package(s)`];
  if (left.length) {
    out.push('', `${left.length} vulnerabilities (${sevSummary(left.map((v) => v.adv.severity))})`);
    if (skipped.length) out.push('', 'To address all issues (including breaking changes), run:', '  npm audit fix --force', C.gray(`  (would install: ${skipped.join(', ')})`));
  } else out.push('found 0 vulnerabilities');
  if (force) out.push(C.yellow('npm WARN using --force Recommended protections disabled.'));
  return res(out);
}

function runTests(ctx: ShellCtx, pkg: PkgJson): CmdResult {
  const out = [`> ${pkg.name ?? 'app'}@${pkg.version ?? '1.0.0'} test`, `> ${pkg.scripts?.test ?? ''}`, ''];
  if (!pkg.scripts?.test) return res(['npm ERR! Missing script: "test"'], 1);
  if (!ctx.installed.jest) return res([...out, 'sh: 1: jest: not found', C.gray('hint: install dependencies first (npm ci)')], 127);
  if (!ctx.tests.length) return res([...out, 'No tests found, exiting with code 0']);
  const suites: Record<string, { name: string; err: string | null }[]> = {};
  for (const t of ctx.tests) (suites[t.suite] ??= []).push({ name: t.name, err: t.run(ctx.fs, ctx.installed) });
  let passed = 0;
  let failed = 0;
  const failures: string[] = [];
  for (const [suite, results] of Object.entries(suites)) {
    out.push(`${results.every((r) => !r.err) ? C.green(' PASS ') : C.red(' FAIL ')} ${suite}`);
    for (const r of results) {
      if (r.err) {
        failed++;
        out.push(`  ${C.red('✕')} ${r.name}`);
        failures.push(C.red(`  ● ${r.name}`), '', ...r.err.split('\n').map((l) => '    ' + l), '');
      } else {
        passed++;
        out.push(`  ${C.green('✓')} ${r.name} ${C.gray(`(${3 + (r.name.length % 9)} ms)`)}`);
      }
    }
  }
  out.push('', ...failures, `Tests:       ${failed ? C.red(`${failed} failed`) + ', ' : ''}${C.green(`${passed} passed`)}, ${passed + failed} total`);
  if (!ctx.pipeline) {
    ctx.flags.testsRev = revOf(ctx.s);
    ctx.flags.testsPassed = failed === 0;
    if (failed) ctx.flags.testsFailedOnce = true;
  }
  return res(out, failed ? 1 : 0);
}

// ---------------------------------------------------------------------------
// scanners

function gitleaks(args: string[], ctx: ShellCtx): CmdResult {
  const sub = args[0];
  if (sub === 'version' || flag(args, '--version')) return res(['v8.21.2']);
  if (!['detect', 'dir', 'git', 'protect'].includes(sub ?? '')) return res(['Usage:', '  gitleaks [command]', '', 'Available Commands:', '  dir     scan directories or files for secrets', '  git     scan git repositories for secrets', '  detect  (deprecated) detect secrets in code'], 1);
  const noGit = sub === 'dir' || sub === 'protect' || flag(args, '--no-git');
  const redact = flag(args, '--redact');
  const exitCode = Number(opt(args, '--exit-code') ?? 1);
  const commits = ancestry(ctx.s.commits, ctx.pipeline ? ctx.commit : ctx.s.head);
  const leaks: Leak[] = noGit ? scanFiles(ctx.fs) : scanHistory(commits, ctx.fs);
  const out = [C.gray('    ○'), C.gray('    │╲'), C.gray('    │ ○'), C.gray('    ○ ░'), C.gray('    ░    gitleaks'), ''];
  for (const l of leaks) {
    const shown = redact ? 'REDACTED' : C.red(l.secret);
    out.push(`Finding:     ${redact ? l.match.replace(l.secret, 'REDACTED') : l.match.replace(l.secret, C.red(l.secret))}`, `Secret:      ${shown}`, `RuleID:      ${l.ruleId}`, `Entropy:     ${l.entropy.toFixed(6)}`, `File:        ${l.file}`, `Line:        ${l.line}`);
    if (l.commit) out.push(`Commit:      ${l.commit.id}`, `Author:      ${l.commit.author.split(' <')[0]}`, `Date:        ${l.commit.date}`);
    out.push(`Fingerprint: ${l.fingerprint}`, '');
  }
  out.push(`${clock()} ${C.green('INF')} ${noGit ? `scanned ~${(Object.values(ctx.fs).join('').length / 1024).toFixed(2)} KB` : `${commits.length} commits scanned.`}`);
  out.push(leaks.length ? `${clock()} ${C.red('WRN')} leaks found: ${leaks.length}` : `${clock()} ${C.green('INF')} no leaks found`);
  const report = opt(args, '--report-path', '-r');
  if (report) ctx.fs[norm(report)] = JSON.stringify(leaks.map((l) => ({ RuleID: l.ruleId, File: l.file, StartLine: l.line, Commit: l.commit?.id ?? '', Secret: redact ? 'REDACTED' : l.secret, Fingerprint: l.fingerprint })), null, 2) + '\n';
  record(ctx, 'gitleaks', leaks.map(leakToFinding), noGit ? 'working tree' : 'git history');
  if (!ctx.pipeline) ctx.flags[noGit ? 'gitleaksDirRev' : 'gitleaksGitRev'] = revOf(ctx.s);
  return res(out, leaks.length ? exitCode : 0);
}

function semgrep(args: string[], ctx: ShellCtx): CmdResult {
  if (flag(args, '--version')) return res(['1.95.0']);
  const sub = args[0] === 'ci' ? 'ci' : 'scan';
  const rest = args[0] === 'scan' || args[0] === 'ci' ? args.slice(1) : args;
  const target = positional(rest, ['--config', '-c', '-f', '-o', '--output', '--exclude'])[0];
  const exclude = opt(rest, '--exclude');
  const scope = Object.fromEntries(Object.entries(ctx.fs).filter(([p]) => (!target || target === '.' || p.startsWith(norm(target))) && (!exclude || !p.startsWith(norm(exclude)))));
  const { matches, scanned } = runSast(scope);
  const active = matches.filter((m) => !m.suppressed);
  const failOn = flag(rest, '--error') || sub === 'ci';
  const out = ['', '┌──── ○○○ ────┐', '│ Semgrep CLI │', '└─────────────┘', '', `Scanning ${scanned} files with ${C.bold('1062 Code rules')} (config: ${opt(rest, '--config', '-c') ?? 'auto'})`, ''];
  if (active.length) {
    out.push(`┌──────────────────┐`, `│ ${String(active.length).padStart(2)} Code Finding${active.length === 1 ? ' ' : 's'} │`, `└──────────────────┘`, '');
    for (const f of [...new Set(active.map((m) => m.file))]) {
      out.push(C.bold(`    ${f}`));
      for (const m of active.filter((x) => x.file === f)) {
        out.push(`   ${m.rule.severity === 'ERROR' ? C.red('❯❯❱') : C.yellow(' ❯❱')} ${C.bold(m.rule.id)}`);
        let buf = '          ';
        for (const w of m.rule.message.split(' ')) {
          if (buf.length + w.length > 92) {
            out.push(buf);
            buf = '          ';
          }
          buf += w + ' ';
        }
        out.push(buf, '', `           ${String(m.line).padStart(3)}┆ ${m.code}`, '');
      }
    }
  }
  const sup = matches.length - active.length;
  out.push('┌──────────────┐', '│ Scan Summary │', '└──────────────┘', `Ran 1062 rules on ${scanned} files: ${active.length} finding${active.length === 1 ? '' : 's'}.${sup ? ` (${sup} ignored via nosemgrep)` : ''}`);
  if (active.length && !failOn) out.push(C.gray('(exit code 0 — add --error to fail CI when findings exist)'));
  record(ctx, 'semgrep', active.map(sastToFinding), target ?? '.');
  if (!ctx.pipeline) ctx.flags.semgrepRev = revOf(ctx.s);
  return res(out, active.length && failOn ? 1 : 0);
}

function totalLine(sevs: string[], extraLow = 0): string {
  const n = (s: string) => sevs.filter((x) => x === s).length;
  return `Total: ${sevs.length + extraLow} (UNKNOWN: 0, LOW: ${n('LOW') + extraLow}, MEDIUM: ${n('MEDIUM')}, HIGH: ${n('HIGH')}, CRITICAL: ${n('CRITICAL')})`;
}

const colorSev = (l: string) => l.replace(/\b(CRITICAL|HIGH|MEDIUM|LOW)\b/, (m) => sevColor(m));
const VULN_HEAD = ['Library', 'Vulnerability', 'Severity', 'Status', 'Installed Version', 'Fixed Version', 'Title'];

function trivy(args: string[], ctx: ShellCtx): CmdResult {
  const [sub, ...rest] = args;
  if (sub === '--version' || sub === 'version') return res(['Version: 0.57.1']);
  const sevFilter = (opt(rest, '--severity', '-s') ?? 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL').split(',');
  const exitCode = Number(opt(rest, '--exit-code') ?? 0);
  const format = opt(rest, '--format', '-f') ?? 'table';
  const output = opt(rest, '--output', '-o');
  const target = positional(rest, ['--severity', '-s', '--exit-code', '--format', '-f', '--output', '-o', '--scanners', '--skip-dirs'])[0] ?? '.';
  const ts = new Date().toISOString().slice(0, 19) + 'Z';
  const info = (m: string) => `${ts}\t${C.blue('INFO')}\t${m}`;
  if (sub === 'fs' || sub === 'filesystem' || sub === 'repo') {
    const lock = readLock(ctx.fs);
    if (format === 'cyclonedx') {
      const doc = sbomCycloneDx(readPkg(ctx.fs).pkg ?? {}, lock ?? {});
      if (!output) return res(doc.split('\n'));
      ctx.fs[norm(output)] = doc;
      if (!ctx.pipeline) ctx.flags.sbomRev = revOf(ctx.s);
      return res([info(`CycloneDX SBOM written to ${output}`)]);
    }
    if (!lock) return res([info('Number of language-specific files\tnum=0'), C.gray('No package-lock.json found — run npm install first.')]);
    const all = auditInstalled(lock);
    const hits = all.filter((h) => sevFilter.includes(h.adv.severity));
    record(ctx, 'trivy-fs', all.map(vulnToFinding), target);
    if (!ctx.pipeline) ctx.flags.trivyFsRev = revOf(ctx.s);
    const out = [info('[vuln] Vulnerability scanning is enabled'), info('Number of language-specific files\tnum=1'), '', 'package-lock.json (npm)', '=======================', totalLine(hits.map((h) => h.adv.severity)), ''];
    if (hits.length) out.push(...boxTable(VULN_HEAD, hits.map((h) => [h.adv.pkg, h.adv.id, h.adv.severity, 'fixed', h.installed, h.adv.fixed, h.adv.title.slice(0, 48)])).map(colorSev));
    return res(out, hits.length ? exitCode : 0);
  }
  if (sub === 'image') {
    const tag = target.includes(':') ? target : target + ':latest';
    const img = ctx.s.images[tag] ?? ctx.s.registry[tag];
    if (!img) return res([`${ts}\t${C.red('FATAL')}\tunable to find the specified image "${tag}" in ["docker" "remote"]`], 1);
    record(ctx, 'trivy-image', imageFindings(img), tag);
    const v = imageVulns(img);
    const os = v.os.filter((o) => sevFilter.includes(o.severity) && (!flag(rest, '--ignore-unfixed') || o.fixed));
    const app = v.app.filter((h) => sevFilter.includes(h.adv.severity));
    const extra = sevFilter.includes('LOW') ? v.extraLow : 0;
    const out = [info(`Detected OS\tfamily="${img.family}" base="${img.base}"`), '', `${tag} (${img.family === 'alpine' ? 'alpine 3.20.3' : 'debian 12.7'})`, '='.repeat(tag.length + 16), totalLine(os.map((o) => o.severity), extra), ''];
    if (os.length) out.push(...boxTable(VULN_HEAD, os.map((o) => [o.pkg, o.id, o.severity, o.fixed ? 'fixed' : 'affected', o.installed, o.fixed, o.title.slice(0, 46)])).map(colorSev));
    if (extra) out.push(C.gray(`  … ${extra} LOW findings not shown (filter with --severity HIGH,CRITICAL)`));
    out.push('', 'Node.js (node-pkg)', '==================', totalLine(app.map((h) => h.adv.severity)), '');
    if (app.length) out.push(...boxTable(VULN_HEAD, app.map((h) => [h.adv.pkg, h.adv.id, h.adv.severity, 'fixed', h.installed, h.adv.fixed, h.adv.title.slice(0, 46)])).map(colorSev));
    const secrets = sevFilter.includes('CRITICAL') ? v.secrets : [];
    if (secrets.length) out.push('', C.red(`Secrets found in image (${secrets.length}): ${secrets.join(', ')}`));
    return res(out, os.length + app.length + secrets.length ? exitCode : 0);
  }
  if (sub === 'config') {
    const out = [info('[misconfig] Misconfiguration scanning is enabled')];
    const findings: Finding[] = [];
    for (const d of Object.keys(ctx.fs).filter((p) => /(^|\/)Dockerfile$/.test(p))) {
      const mis = trivyConfigDockerfile(ctx.fs[d]).filter((m) => sevFilter.includes(m.severity));
      out.push('', `${d} (dockerfile)`, '='.repeat(d.length + 13), `Tests: ${mis.length + 23} (SUCCESSES: 23, FAILURES: ${mis.length})`, totalLine(mis.map((m) => m.severity)).replace('Total', 'Failures'), '');
      for (const m of mis) {
        out.push(`${m.avd} (${sevColor(m.severity)}): ${m.message}`, '═'.repeat(60), m.title, C.gray(` ${d}:${m.line}`), C.gray(` Resolution: ${m.resolution}`), '');
        findings.push({ tool: 'trivy-config', ruleId: m.id, severity: m.severity, title: m.title, file: d, line: m.line, detail: m.message, remediation: m.resolution });
      }
    }
    record(ctx, 'trivy-config', findings, '.');
    return res(out, findings.length ? exitCode : 0);
  }
  return res(['Usage:', '  trivy <command> [flags] target', '', 'Scanning Commands:', '  config      Scan for misconfigurations', '  fs          Scan local filesystem', '  image       Scan a container image'], 1);
}

function syft(args: string[], ctx: ShellCtx): CmdResult {
  const o = opt(args, '-o', '--output') ?? 'table';
  const lock = readLock(ctx.fs);
  if (!lock) return res([' ✔ Indexed file system', 'No packages discovered (is package-lock.json present?)']);
  const [fmt, file] = o.split('=');
  if (fmt.startsWith('cyclonedx')) {
    const doc = sbomCycloneDx(readPkg(ctx.fs).pkg ?? {}, lock, 'syft');
    if (!file) return res(doc.split('\n'));
    ctx.fs[norm(file)] = doc;
    if (!ctx.pipeline) ctx.flags.sbomRev = revOf(ctx.s);
    return res([' ✔ Indexed file system', ` ✔ Cataloged contents  ${Object.keys(lock).length} packages`, ` ✔ Wrote cyclonedx-json to ${file}`]);
  }
  return res(['NAME            VERSION    TYPE', ...Object.entries(lock).map(([n, v]) => `${n.padEnd(16)}${v.padEnd(11)}npm`)]);
}

function hadolintCmd(args: string[], ctx: ShellCtx): CmdResult {
  if (flag(args, '--version', '-v')) return res(['Haskell Dockerfile Linter 2.12.0']);
  const file = norm(positional(args, ['--failure-threshold', '-t', '--ignore'])[0] ?? 'Dockerfile');
  const src = ctx.fs[file];
  if (src === undefined) return res([`${file}: openBinaryFile: does not exist (No such file or directory)`], 1);
  const cfg = ctx.fs['.hadolint.yaml'] ?? '';
  const ignored = [...args.flatMap((x, i) => (x === '--ignore' && args[i + 1] ? [args[i + 1]] : [])), ...[...cfg.matchAll(/-\s*(DL\d{4})/g)].map((m) => m[1])];
  const threshold = opt(args, '--failure-threshold', '-t') ?? /failure-threshold:\s*(\w+)/.exec(cfg)?.[1] ?? 'info';
  const { hits, error } = hadolint(src, ignored);
  if (error) return res([`${file}:1 ${error}`], 1);
  const levels = ['style', 'info', 'warning', 'error'];
  const color = (l: string) => (l === 'error' ? C.red(l) : l === 'warning' ? C.yellow(l) : C.cyan(l));
  record(ctx, 'hadolint', hits.map((h) => ({ tool: 'hadolint' as const, ruleId: h.rule, severity: hadolintSeverity[h.level], title: h.msg, file, line: h.line, remediation: `https://github.com/hadolint/hadolint/wiki/${h.rule}` })), file);
  const fail = threshold !== 'none' && hits.some((h) => levels.indexOf(h.level) >= levels.indexOf(threshold));
  return res(hits.map((h) => `${file}:${h.line} ${C.bold(h.rule)} ${color(h.level)}: ${h.msg}`), fail ? 1 : 0);
}

function docker(args: string[], ctx: ShellCtx): CmdResult {
  const [sub, ...rest] = args;
  const s = ctx.s;
  const find = (t: string) => s.images[t.includes(':') ? t : t + ':latest'] ?? s.registry[t.includes(':') ? t : t + ':latest'];
  switch (sub) {
    case 'build': {
      const tag = opt(rest, '-t', '--tag') ?? `local-${Date.now().toString(16)}:latest`;
      const full = tag.includes(':') ? tag : tag + ':latest';
      const r = dockerBuild(ctx.fs, full, norm(opt(rest, '-f', '--file') ?? 'Dockerfile'));
      if (r.ok && r.image) {
        s.images[full] = r.image;
        if (!ctx.pipeline) {
          ctx.flags.lastBuiltImage = full;
          ctx.flags.lastBuiltRev = revOf(s);
        }
      }
      return res(r.log.map((l) => (l.startsWith('ERROR') ? C.red(l) : l)), r.ok ? 0 : 1);
    }
    case 'images':
      return res(['REPOSITORY                                 TAG        SIZE', ...Object.values(s.images).map((i) => `${i.tag.split(':').slice(0, -1).join(':').padEnd(43)}${i.tag.split(':').pop()!.padEnd(11)}${i.sizeMb}MB`)]);
    case 'tag': {
      const [src, dst] = positional(rest);
      const img = find(src ?? '');
      if (!img || !dst) return res([`Error response from daemon: No such image: ${src}`], 1);
      const t = dst.includes(':') ? dst : dst + ':latest';
      s.images[t] = { ...img, tag: t };
      return res([]);
    }
    case 'push': {
      const t = positional(rest)[0] ?? '';
      const tag = t.includes(':') ? t : t + ':latest';
      const img = s.images[tag];
      if (!img) return res([`An image does not exist locally with the tag: ${t}`], 1);
      if (!tag.startsWith('registry.shopflow.local/')) return res([`The push refers to repository [docker.io/library/${tag.split(':')[0]}]`, 'denied: requested access to the resource is denied', C.gray('hint: the company registry is registry.shopflow.local/')], 1);
      s.registry[tag] = img;
      return res([`The push refers to repository [${tag.split(':')[0]}]`, '5f70bf18a086: Pushed', `${tag.split(':').pop()}: digest: sha256:${hexDigest(tag, 64)} size: 1789`]);
    }
    case 'run': {
      const pos = positional(rest, ['-p', '-e', '--name', '--env-file', '-v', '--user', '-u', '--network']);
      if (!pos[0]) return res(['"docker run" requires at least 1 argument.'], 1);
      if (/zaproxy|zap/.test(pos[0]) && pos[1]) return zap(pos[1], rest.slice(rest.indexOf(pos[1]) + 1), ctx);
      const img = find(pos[0]);
      if (!img) return res([`Unable to find image '${pos[0]}' locally`, `docker: Error response from daemon: pull access denied for ${pos[0].split(':')[0]}.`], 125);
      const u = opt(rest, '--user', '-u');
      const r = dockerRun(u ? { ...img, user: u } : img);
      if (!ctx.pipeline) s.container = { image: img.tag, ok: r.ok, log: r.log };
      return res(flag(rest, '-d', '--detach') && r.ok ? [hexDigest(img.tag + Date.now(), 64)] : r.log.map((l) => (r.ok ? l : C.red(l))), r.ok ? 0 : 125);
    }
    case 'ps':
      return res(['CONTAINER ID   IMAGE                          STATUS', ...(s.container ? [`a1b2c3d4e5f6   ${s.container.image.padEnd(31)}${s.container.ok ? 'Up 12 seconds' : 'Exited (1)'}`] : [])]);
    case 'logs':
      return res(s.container?.log ?? ['Error: No such container'], s.container ? 0 : 1);
    case 'inspect': {
      const img = find(positional(rest)[0] ?? '');
      if (!img) return res(['Error: No such object'], 1);
      return res(JSON.stringify([{ RepoTags: [img.tag], Config: { User: img.user, Env: Object.entries(img.env).map(([k, v]) => `${k}=${v}`), Cmd: img.cmd, Healthcheck: img.healthcheck }, SizeMB: img.sizeMb }], null, 2).split('\n'));
    }
    case 'history': {
      const img = find(positional(rest)[0] ?? '');
      if (!img) return res(['Error response from daemon: No such image'], 1);
      return res(['CREATED BY                                            SIZE', ...Object.entries(img.env).map(([k, v]) => `ENV ${k}=${v}`.padEnd(54) + '0B'), ...img.packages.map((p) => `RUN install ${p}`.padEnd(54) + '18MB'), `FROM ${img.base}`.padEnd(54) + `${img.sizeMb}MB`]);
    }
    case 'version':
    case '--version':
      return res(['Docker version 27.3.1']);
    default:
      return res([`docker: '${sub ?? ''}' is not supported here (build, run, images, tag, push, ps, logs, inspect, history).`], 1);
  }
}

function checkovCmd(args: string[], ctx: ShellCtx): CmdResult {
  if (flag(args, '--version', '-v')) return res(['3.2.296']);
  const dir = opt(args, '-d', '--directory') ?? '';
  const file = opt(args, '-f', '--file');
  if (file && ctx.fs[norm(file)] === undefined) return res([`[ERROR] File ${file} does not exist`], 1);
  const skip = args.flatMap((x, i) => (x === '--skip-check' && args[i + 1] ? args[i + 1].split(',') : []));
  const run = checkov(file ? { [norm(file)]: ctx.fs[norm(file)] } : ctx.fs, file ? '' : dir, skip);
  const failed = run.results.filter((r) => r.status === 'FAILED');
  const passed = run.results.filter((r) => r.status === 'PASSED');
  const skipped = run.results.filter((r) => r.status === 'SKIPPED');
  const out = [C.magenta('       _               _'), C.magenta('   ___| |__   ___  ___| | _______   __'), C.magenta("  / __| '_ \\ / _ \\/ __| |/ / _ \\ \\ / /"), C.magenta(' | (__| | | |  __/ (__|   < (_) \\ V /'), C.magenta('  \\___|_| |_|\\___|\\___|_|\\_\\___/ \\_/'), '', 'version: 3.2.296', ''];
  if (run.parseErrors.length) out.push(C.yellow(`Failed to parse: ${run.parseErrors.join('; ')}`), '');
  if (!run.resourceCount) return res([...out, C.gray(`No Terraform resources found in ${dir || file || '.'}`)]);
  out.push('terraform scan results:', '', `Passed checks: ${passed.length}, Failed checks: ${failed.length}, Skipped checks: ${skipped.length}`, '');
  const show = (r: (typeof run.results)[number]) => {
    const col = r.status === 'PASSED' ? C.green : r.status === 'FAILED' ? C.red : C.yellow;
    out.push(`Check: ${r.id}: "${r.name}"`, '\t' + col(`${r.status} for resource: ${r.resource}`), `\tFile: ${r.file}:${r.lines[0]}-${r.lines[1]}`);
    if (r.status === 'SKIPPED') out.push(`\tSuppress comment: ${r.skipReason}`);
    if (r.status === 'FAILED') {
      out.push(`\tGuide: ${C.blue(r.guide)}`);
      if (!flag(args, '--compact')) (ctx.fs[r.file.slice(1)] ?? '').split('\n').slice(r.lines[0] - 1, r.lines[1]).forEach((l, i) => out.push(C.gray(`\t\t${String(r.lines[0] + i).padStart(3)} | ${l}`)));
    }
    out.push('');
  };
  if (!flag(args, '--quiet')) passed.forEach(show);
  failed.forEach(show);
  skipped.forEach(show);
  record(ctx, 'checkov', failed.map(checkToFinding), dir || file || '.');
  if (!ctx.pipeline) ctx.flags.checkovRev = revOf(ctx.s);
  return res(out, failed.length && !flag(args, '--soft-fail') ? 1 : 0);
}

function terraform(args: string[], ctx: ShellCtx): CmdResult {
  const chdir = args.find((a) => a.startsWith('-chdir='))?.slice(7);
  const sub = args.find((a) => !a.startsWith('-'));
  const dir = chdir ? norm(chdir).replace(/\/$/, '') : 'infra';
  if (sub === 'version') return res(['Terraform v1.9.8 on linux_amd64']);
  const tf = Object.fromEntries(Object.entries(ctx.fs).filter(([p]) => p.endsWith('.tf') && p.startsWith(dir + '/')));
  const err = (t: string, ...d: string[]) => [C.red('╷'), C.red(`│ Error: ${t}`), '│', ...d.map((x) => `│ ${x}`), C.red('╵')];
  if (!Object.keys(tf).length) return res(err('No configuration files', `No .tf files found in ./${dir}.`), 1);
  const { resources, diags } = resourcesOf(tf);
  if (sub === 'init') {
    ctx.flags.tfInit = true;
    return res(['', C.bold('Initializing provider plugins...'), '- Installing hashicorp/aws v5.74.0...', '', C.green(C.bold('Terraform has been successfully initialized!'))]);
  }
  const diagOut = diags.flatMap((d) => err(d.diag.summary, `  on ${d.file} line ${d.diag.line}:`, d.diag.detail));
  if (sub === 'validate' || sub === 'plan') {
    if (!ctx.flags.tfInit) return res(err('Missing required provider', 'This configuration requires provider registry.terraform.io/hashicorp/aws.', 'Run "terraform init" first.'), 1);
    if (diags.length) return res(diagOut, 1);
  }
  if (sub === 'validate') {
    ctx.flags.tfValidRev = revOf(ctx.s);
    return res([C.green('Success! The configuration is valid.')]);
  }
  if (sub === 'plan') {
    const out = ['', 'Terraform will perform the following actions:', ''];
    for (const r of resources) {
      out.push(C.bold(`  # ${r.type}.${r.name}`) + ' will be created', `  ${C.green('+')} resource "${r.type}" "${r.name}" {`);
      for (const [k, v] of Object.entries(r.block.attrs)) out.push(`      ${C.green('+')} ${k.padEnd(28)}= ${v.raw.split('\n')[0]}${v.raw.includes('\n') ? ' …' : ''}`);
      for (const b of r.block.blocks) out.push(`      ${C.green('+')} ${b.type} { … }`);
      out.push('    }', '');
    }
    out.push(C.bold(`Plan: ${resources.length} to add, 0 to change, 0 to destroy.`));
    return res(out);
  }
  if (sub === 'fmt') return res([]);
  if (sub === 'apply') return res([C.yellow('terraform apply is disabled in this lab — infrastructure is applied by the pipeline after review.')], 1);
  return res(['Usage: terraform [-chdir=DIR] <init|validate|plan|fmt>'], 1);
}

function kubectl(args: string[], ctx: ShellCtx): CmdResult {
  const s = ctx.s;
  const [sub] = args;
  if (sub === 'apply') {
    const f = opt(args, '-f', '--filename');
    if (!f) return res(['error: must specify one of -f and -k'], 1);
    const path = norm(f).replace(/\/$/, '');
    const targets = Object.keys(ctx.fs).filter((p) => (p === path || p.startsWith(path + '/')) && /\.ya?ml$/.test(p));
    if (!targets.length) return res([`error: the path "${f}" does not exist`], 1);
    const out: string[] = [];
    for (const t of targets) {
      const { workloads, error } = parseWorkloads(ctx.fs[t]);
      if (error) return res([error], 1);
      for (const w of workloads) {
        const v = kyverno(w);
        if (v.length) return res([...out, ...denyMessage(w, t, v)], 1);
        out.push(`${w.kind.toLowerCase()}.apps/${w.name} configured`);
        if (w.kind === 'Deployment') {
          const r = rollout(String(w.containers[0]?.image ?? ''), s.registry, ctx.pipeline ? ctx.commit : s.head);
          out.push(...r.log);
          if (!r.ok) return res(out, 1);
          s.staging = r.dep!;
        }
      }
    }
    return res(out);
  }
  if (sub === 'set' && args[1] === 'image') {
    const image = args.find((x) => x.includes('='))?.split('=')[1] ?? '';
    if (!image.includes(':') || image.endsWith(':latest')) return res(['error: admission webhook "validate.kyverno.svc-fail" denied the request: disallow-latest-tag: Using a mutable image tag is not allowed.'], 1);
    const r = rollout(image, s.registry, ctx.pipeline ? ctx.commit : s.head);
    if (r.ok) s.staging = r.dep!;
    return res(['deployment.apps/shopflow-api image updated', ...r.log], r.ok ? 0 : 1);
  }
  if (sub === 'rollout') return s.staging ? res(['deployment "shopflow-api" successfully rolled out']) : res(['Error from server (NotFound): deployments.apps "shopflow-api" not found'], 1);
  if (sub === 'get') return s.staging ? res(['NAME                         READY   STATUS    RESTARTS   AGE', 'shopflow-api-7c9d5b-xk2lp    1/1     Running   0          42s', 'shopflow-api-7c9d5b-qq81z    1/1     Running   0          40s', C.gray(`image: ${s.staging.image}`)]) : res(['No resources found in shop namespace.']);
  return res(['kubectl: apply -f, get pods, set image, rollout status'], sub ? 1 : 0);
}

function kyvernoCmd(args: string[], ctx: ShellCtx): CmdResult {
  if (args[0] !== 'apply') return res(['Usage: kyverno apply <policy-dir> --resource <file>'], 1);
  const r = opt(args, '--resource', '-r');
  if (!r) return res(['Error: --resource is required'], 1);
  const src = ctx.fs[norm(r)];
  if (src === undefined) return res([`Error: failed to load resources: open ${r}: no such file or directory`], 1);
  const { workloads, error } = parseWorkloads(src);
  if (error) return res([error], 1);
  const out = [`Applying 5 policy rule(s) to ${workloads.length} resource(s)...`, ''];
  const findings: Finding[] = [];
  let fails = 0;
  for (const w of workloads) {
    const v = kyverno(w);
    fails += v.length;
    findings.push(...kyvernoFindings(w, norm(r)));
    v.forEach((x, i) => out.push(C.red(`policy ${x.policy} -> resource ${w.namespace}/${w.kind}/${w.name} failed:`), `${i + 1}. ${x.rule}: ${x.message}`, ''));
  }
  record(ctx, 'kyverno', findings, norm(r));
  out.push(`pass: ${5 * workloads.length - fails}, fail: ${fails}, warn: 0, error: 0, skip: 0`);
  return res(out, fails ? 1 : 0);
}

function aws(args: string[], ctx: ShellCtx): CmdResult {
  const s = ctx.s;
  const [svc, op, ...rest] = args;
  const json = (o: unknown) => res(JSON.stringify(o, null, 4).split('\n'));
  if (svc === 'sts' && op === 'get-caller-identity') return json({ UserId: 'AIDATRAININGUSER', Account: '000000000000', Arn: 'arn:aws:iam::000000000000:user/devsecops-trainee' });
  if (svc === 'iam') {
    const user = opt(rest, '--user-name');
    if (op === 'list-access-keys') return json({ AccessKeyMetadata: s.iamKeys.filter((k) => !user || k.user === user).map((k) => ({ UserName: k.user, AccessKeyId: k.id, Status: k.status, CreateDate: k.created })) });
    if (op === 'update-access-key' || op === 'delete-access-key') {
      const id = opt(rest, '--access-key-id');
      const k = s.iamKeys.find((x) => x.id === id);
      if (!k) return res([`An error occurred (NoSuchEntity): The Access Key with id ${id} cannot be found.`], 254);
      if (op === 'delete-access-key') s.iamKeys.splice(s.iamKeys.indexOf(k), 1);
      else {
        const st = opt(rest, '--status');
        if (st !== 'Active' && st !== 'Inactive') return res(['aws: error: argument --status: valid choices are: Active | Inactive'], 252);
        k.status = st;
      }
      return res([]);
    }
    if (op === 'create-access-key') {
      const u = user ?? 'unknown';
      if (s.iamKeys.filter((k) => k.user === u).length >= 2) return res(['An error occurred (LimitExceeded): Cannot exceed quota for AccessKeysPerUser: 2'], 254);
      const id = 'AKIATRAINING' + hexDigest(u + Date.now(), 8).toUpperCase();
      s.iamKeys.push({ id, user: u, status: 'Active', created: new Date().toISOString() });
      return json({ AccessKey: { UserName: u, AccessKeyId: id, Status: 'Active', SecretAccessKey: '(shown once — store it in a secrets manager, not in code)' } });
    }
  }
  if (svc === 'cloudtrail' && op === 'lookup-events') {
    const key = /AttributeValue=(\S+)/.exec(opt(rest, '--lookup-attributes') ?? '')?.[1];
    if (key && key === String(ctx.flags.leakedKeyId ?? '')) {
      if (!ctx.pipeline) ctx.flags.investigatedKey = true;
      return json({
        Events: [
          { EventTime: '2026-10-13T09:00:12Z', EventName: 'PutObject', AccessKeyId: key, SourceIPAddress: '10.20.4.18', UserAgent: 'aws-sdk-nodejs/3.6' },
          { EventTime: '2026-10-14T02:13:44Z', EventName: 'ListBuckets', AccessKeyId: key, SourceIPAddress: '203.0.113.47', UserAgent: 'aws-cli/2.15.0 (unknown host)' },
        ],
      });
    }
    return json({ Events: [] });
  }
  return res(['Supported here: aws iam list-access-keys | update-access-key | delete-access-key | create-access-key, aws sts get-caller-identity, aws cloudtrail lookup-events'], svc ? 252 : 0);
}

function targetApp(url: string, ctx: ShellCtx): { app: RunningApp | null; error: string | null; path: string } {
  let u: URL;
  try {
    u = new URL(url.includes('://') ? url : 'http://' + url);
  } catch {
    return { app: null, error: 'curl: (3) URL using bad/illegal format', path: '/' };
  }
  const path = u.pathname + u.search;
  if (u.hostname === STAGING_HOST) return ctx.s.staging ? { app: ctx.s.staging, error: null, path } : { app: null, error: `curl: (7) Failed to connect to ${STAGING_HOST} port 443: nothing deployed yet`, path };
  if (u.hostname === 'localhost' || u.hostname === '127.0.0.1') {
    const c = ctx.s.container;
    const img = c?.ok ? (ctx.s.images[c.image] ?? ctx.s.registry[c.image]) : undefined;
    return img ? { app: img, error: null, path } : { app: null, error: `curl: (7) Failed to connect to localhost port ${u.port || 80}: Connection refused`, path };
  }
  return { app: null, error: `curl: (6) Could not resolve host: ${u.hostname}`, path };
}

function curl(args: string[], ctx: ShellCtx): CmdResult {
  const url = positional(args, ['-X', '--request', '-d', '--data', '-H', '--header', '-o'])[0];
  if (!url) return res(["curl: try 'curl --help' for more information"], 2);
  const head = flag(args, '-I', '--head');
  const body = opt(args, '-d', '--data');
  const method = (opt(args, '-X', '--request') ?? (body ? 'POST' : 'GET')).toUpperCase();
  const t = targetApp(url, ctx);
  if (!t.app) return res([t.error ?? 'curl: (7) connection refused'], 7);
  const r = httpRequest(t.app, method, t.path, body);
  const out: string[] = [];
  if (head || flag(args, '-i', '--include', '-v')) out.push(`HTTP/1.1 ${r.status} ${r.statusText}`, ...Object.entries(r.headers).map(([k, v]) => `${k}: ${v}`), '');
  if (!head) out.push(r.body);
  return res(out, flag(args, '-f', '--fail') && r.status >= 400 ? 22 : 0);
}

function zap(tool: string, args: string[], ctx: ShellCtx): CmdResult {
  const target = opt(args, '-t');
  if (!target) return res([`Usage: ${tool} -t <target> [-c rules.tsv] [-I] [-r report.html]`, '    -I   do not return failure on warning'], 3);
  const t = targetApp(target, ctx);
  if (!t.app) return res([`Failed to access URL: ${target}`, t.error ?? ''], 3);
  const active = tool !== 'zap-baseline.py';
  const alerts = zapAlerts(t.app, target.replace(/\/$/, ''), active);
  const levels: Record<string, string> = {};
  const cfg = opt(args, '-c');
  if (cfg) {
    const src = ctx.fs[norm(cfg)];
    if (src === undefined) return res([`Failed to load config file ${cfg}`], 3);
    for (const l of src.split('\n')) {
      const m = /^(\d+)\s+(IGNORE|INFO|WARN|FAIL)/.exec(l.trim());
      if (m) levels[m[1]] = m[2];
    }
  }
  const out = [`Total of ${active ? 14 : 9} URLs`, 'PASS: Vulnerable JS Library (Powered by Retire.js) [10003]', 'PASS: Cookie Poisoning [10029]', 'PASS: Information Disclosure - Sensitive Information in URL [10024]', 'PASS: Timestamp Disclosure [10096]'];
  let warn = 0;
  let fail = 0;
  let ign = 0;
  for (const a of alerts) {
    const lvl = levels[a.id] ?? (a.risk === 'High' && active ? 'FAIL' : 'WARN');
    if (lvl === 'IGNORE') {
      ign++;
      out.push(C.gray(`IGNORE: ${a.name} [${a.id}] x ${a.urls.length}`));
      continue;
    }
    if (lvl === 'FAIL') fail++;
    else warn++;
    out.push((lvl === 'FAIL' ? C.red('FAIL-NEW: ') : C.yellow('WARN-NEW: ')) + `${a.name} [${a.id}] x ${a.urls.length} ${C.gray(`(${a.risk})`)}`, ...a.urls.slice(0, 3).map((u) => `\t${u} (200 OK)`));
  }
  out.push(`FAIL-NEW: ${fail}\tFAIL-INPROG: 0\tWARN-NEW: ${warn}\tWARN-INPROG: 0\tINFO: 0\tIGNORE: ${ign}\tPASS: 52`);
  const report = opt(args, '-r');
  if (report) ctx.fs[norm(report)] = `<html><body><h1>ZAP Scanning Report</h1><p>Site: ${target}</p><ul>${alerts.map((a) => `<li>[${a.risk}] ${a.name} (${a.id})</li>`).join('')}</ul></body></html>\n`;
  if (!ctx.pipeline) {
    record(ctx, 'zap', alerts.filter((a) => levels[a.id] !== 'IGNORE').map(zapToFinding), target);
    if (t.app === ctx.s.staging) ctx.flags[active ? 'zapFullAt' : 'zapBaseAt'] = ctx.s.staging!.at;
  }
  return res(out, fail ? 1 : warn && !flag(args, '-I') ? 2 : 0);
}

export const COMMANDS = ['help', 'clear', 'ls', 'cat', 'grep', 'head', 'tail', 'echo', 'touch', 'rm', 'cp', 'mv', 'tree', 'git', 'npm', 'gitleaks', 'semgrep', 'trivy', 'syft', 'hadolint', 'docker', 'checkov', 'terraform', 'kubectl', 'kyverno', 'aws', 'curl', 'zap-baseline.py', 'zap-full-scan.py'];
