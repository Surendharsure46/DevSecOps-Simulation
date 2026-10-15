// Minimal HCL (Terraform) parser: blocks with labels, attributes (including multi-line
// lists/maps), comments. Produces Terraform-style diagnostics for structural errors.

export interface HclAttr {
  raw: string;
  line: number;
}

export interface HclBlock {
  type: string;
  labels: string[];
  attrs: Record<string, HclAttr>;
  blocks: HclBlock[];
  comments: string[];
  startLine: number;
  endLine: number;
}

export interface HclDiag {
  line: number;
  summary: string;
  detail: string;
}

function depthDelta(s: string): number {
  let d = 0;
  let q = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '"' && s[i - 1] !== '\\') q = !q;
    if (q) continue;
    if (c === '{' || c === '[' || c === '(') d++;
    if (c === '}' || c === ']' || c === ')') d--;
  }
  return d;
}

function splitComment(line: string): { code: string; comment: string | null } {
  let q = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"' && line[i - 1] !== '\\') q = !q;
    if (q) continue;
    if (c === '#') return { code: line.slice(0, i), comment: line.slice(i + 1) };
    if (c === '/' && line[i + 1] === '/') return { code: line.slice(0, i), comment: line.slice(i + 2) };
  }
  return { code: line, comment: null };
}

export function parseHcl(src: string): { blocks: HclBlock[]; diags: HclDiag[] } {
  const lines = src.split(/\r?\n/);
  const root: HclBlock = { type: '', labels: [], attrs: {}, blocks: [], comments: [], startLine: 0, endLine: lines.length };
  const stack: HclBlock[] = [root];
  const diags: HclDiag[] = [];
  let pending: { key: string; raw: string; line: number; depth: number } | null = null;

  for (let i = 0; i < lines.length; i++) {
    const no = i + 1;
    const { code, comment } = splitComment(lines[i]);
    const cur = stack[stack.length - 1];
    if (comment !== null) cur.comments.push(comment.trim());
    const t = code.trim();

    if (pending) {
      pending.raw += '\n' + t;
      pending.depth += depthDelta(t);
      if (pending.depth <= 0) {
        cur.attrs[pending.key] = { raw: pending.raw.trim(), line: pending.line };
        pending = null;
      }
      continue;
    }
    if (!t) continue;

    if (t === '}') {
      if (stack.length === 1) {
        diags.push({ line: no, summary: 'Argument or block definition required', detail: 'An argument or block definition is required here. Unexpected "}".' });
        continue;
      }
      stack.pop()!.endLine = no;
      continue;
    }

    const blockM = /^([A-Za-z_][\w-]*)((?:\s+"[^"]*"|\s+[A-Za-z_][\w-]*)*)\s*\{\s*(\})?$/.exec(t);
    if (blockM && !t.includes('=')) {
      const labels = [...blockM[2].matchAll(/"([^"]*)"|([A-Za-z_][\w-]*)/g)].map((m) => m[1] ?? m[2]);
      const b: HclBlock = { type: blockM[1], labels, attrs: {}, blocks: [], comments: [], startLine: no, endLine: no };
      cur.blocks.push(b);
      if (!blockM[3]) stack.push(b);
      continue;
    }

    const attrM = /^([A-Za-z_][\w-]*)\s*=\s*(.*)$/.exec(t);
    if (attrM) {
      const key = attrM[1];
      const raw = attrM[2];
      if (!raw) {
        diags.push({ line: no, summary: 'Invalid expression', detail: `Expected the start of an expression, but found the end of the line (argument "${key}").` });
        continue;
      }
      if (key in cur.attrs) diags.push({ line: no, summary: 'Attribute redefined', detail: `The argument "${key}" was already set at line ${cur.attrs[key].line}.` });
      const d = depthDelta(raw);
      if (d > 0) pending = { key, raw, line: no, depth: d };
      else cur.attrs[key] = { raw: raw.trim(), line: no };
      continue;
    }

    diags.push({ line: no, summary: 'Argument or block definition required', detail: `An argument or block definition is required here. To set an argument, use the equals sign "=". (near: ${t.slice(0, 40)})` });
  }
  if (stack.length > 1) {
    const b = stack[stack.length - 1];
    diags.push({ line: b.startLine, summary: 'Unclosed configuration block', detail: `There is no closing brace for this block before the end of the file. (${b.type} ${b.labels.map((l) => `"${l}"`).join(' ')})` });
  }
  if (pending) diags.push({ line: pending.line, summary: 'Missing closing bracket', detail: `The value for "${pending.key}" is never closed.` });
  return { blocks: root.blocks, diags };
}

export function hStr(a: HclAttr | undefined): string | null {
  if (!a) return null;
  const m = /^"([^"]*)"$/.exec(a.raw.trim());
  return m ? m[1] : a.raw.trim();
}

export function hBool(a: HclAttr | undefined): boolean | null {
  if (!a) return null;
  const v = a.raw.trim();
  if (v === 'true') return true;
  if (v === 'false') return false;
  return null;
}

export function hNum(a: HclAttr | undefined): number | null {
  if (!a) return null;
  const n = Number(a.raw.trim());
  return Number.isFinite(n) ? n : null;
}

export function hList(a: HclAttr | undefined): string[] {
  if (!a) return [];
  return [...a.raw.matchAll(/"([^"]*)"/g)].map((m) => m[1]);
}

export interface Resource {
  type: string;
  name: string;
  block: HclBlock;
  file: string;
}

export function resourcesOf(files: Record<string, string>): { resources: Resource[]; diags: { file: string; diag: HclDiag }[] } {
  const resources: Resource[] = [];
  const diags: { file: string; diag: HclDiag }[] = [];
  for (const [path, text] of Object.entries(files)) {
    if (!path.endsWith('.tf')) continue;
    const { blocks, diags: d } = parseHcl(text);
    d.forEach((diag) => diags.push({ file: path, diag }));
    for (const b of blocks) if (b.type === 'resource' && b.labels.length === 2) resources.push({ type: b.labels[0], name: b.labels[1], block: b, file: path });
  }
  return { resources, diags };
}

/** Find nested blocks anywhere below `b` with the given type. */
export function findBlocks(b: HclBlock, type: string): HclBlock[] {
  const out: HclBlock[] = [];
  for (const c of b.blocks) {
    if (c.type === type) out.push(c);
    out.push(...findBlocks(c, type));
  }
  return out;
}

/** The resource name referenced by e.g. `bucket = aws_s3_bucket.invoices.id`. */
export function refName(a: HclAttr | undefined, type: string): string | null {
  if (!a) return null;
  const m = new RegExp(`${type}\\.([\\w-]+)`).exec(a.raw);
  return m ? m[1] : null;
}
