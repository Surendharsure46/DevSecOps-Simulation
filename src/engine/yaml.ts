// A small YAML subset parser: block maps, block sequences, scalars, flow lists/maps,
// literal/folded block scalars and comments. Enough for GitHub Actions workflows and
// Kubernetes manifests; errors carry the offending line like real YAML linters.

export class YamlError extends Error {
  constructor(
    message: string,
    public line: number,
  ) {
    super(message);
  }
}

interface Line {
  indent: number;
  text: string;
  no: number;
}

function stripComment(s: string): string {
  let q: string | null = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) {
      if (c === q) q = null;
    } else if (c === '"' || c === "'") q = c;
    else if (c === '#' && (i === 0 || /\s/.test(s[i - 1]))) return s.slice(0, i);
  }
  return s;
}

function splitTop(s: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let q: string | null = null;
  let cur = '';
  for (const c of s) {
    if (q) {
      if (c === q) q = null;
      cur += c;
      continue;
    }
    if (c === '"' || c === "'") q = c;
    if (c === '[' || c === '{') depth++;
    if (c === ']' || c === '}') depth--;
    if (c === ',' && depth === 0) {
      out.push(cur.trim());
      cur = '';
    } else cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

export function scalar(v: string): unknown {
  const s = v.trim();
  if (s.startsWith('"') && s.endsWith('"') && s.length >= 2)
    return s.slice(1, -1).replace(/\\n/g, '\n').replace(/\\"/g, '"').replace(/\\\\/g, '\\');
  if (s.startsWith("'") && s.endsWith("'") && s.length >= 2) return s.slice(1, -1).replace(/''/g, "'");
  if (s.startsWith('[') && s.endsWith(']')) return splitTop(s.slice(1, -1)).map(scalar);
  if (s.startsWith('{') && s.endsWith('}')) {
    const o: Record<string, unknown> = {};
    for (const part of splitTop(s.slice(1, -1))) {
      const i = part.indexOf(':');
      if (i > 0) o[String(scalar(part.slice(0, i)))] = scalar(part.slice(i + 1));
    }
    return o;
  }
  if (s === 'true' || s === 'True') return true;
  if (s === 'false' || s === 'False') return false;
  if (s === '' || s === '~' || s === 'null') return null;
  if (/^-?\d+(\.\d+)?$/.test(s)) return Number(s);
  return s;
}

const KEY_RE = /^("[^"]*"|'[^']*'|[^\s"'#:-][^:]*?|-[^\s:][^:]*?)\s*:(?:\s+(.*)|$)/;

export function parseYaml(src: string): unknown {
  const raw = src.replace(/\t/g, '  ').split(/\r?\n/);
  const lines: Line[] = raw.map((r, i) => {
    const t = stripComment(r);
    if (!t.trim()) return { indent: -1, text: '', no: i + 1 };
    return { indent: r.length - r.trimStart().length, text: t.trim(), no: i + 1 };
  });
  let pos = 0;

  const skip = () => {
    while (pos < lines.length && lines[pos].indent < 0) pos++;
  };
  const isItem = (t: string) => t === '-' || t.startsWith('- ');

  function blockScalar(parentIndent: number, style: string): string {
    const body: string[] = [];
    let blockIndent = -1;
    while (pos < raw.length) {
      const r = raw[pos].replace(/\t/g, '  ');
      if (!r.trim()) {
        body.push('');
        pos++;
        continue;
      }
      const ind = r.length - r.trimStart().length;
      if (ind <= parentIndent) break;
      if (blockIndent < 0) blockIndent = ind;
      body.push(r.slice(Math.min(blockIndent, ind)));
      pos++;
    }
    while (body.length && body[body.length - 1] === '') body.pop();
    const text = style.startsWith('>') ? body.join(' ').replace(/ {2,}/g, ' ') : body.join('\n');
    return style.endsWith('-') ? text : text + '\n';
  }

  function parseNode(minIndent: number): unknown {
    skip();
    if (pos >= lines.length) return null;
    const l = lines[pos];
    if (l.indent < minIndent) return null;
    return isItem(l.text) ? parseList(l.indent) : parseMap(l.indent);
  }

  function parseList(indent: number): unknown[] {
    const arr: unknown[] = [];
    for (;;) {
      skip();
      if (pos >= lines.length) break;
      const l = lines[pos];
      if (l.indent < indent) break;
      if (l.indent > indent) throw new YamlError('bad indentation of a sequence entry', l.no);
      if (!isItem(l.text)) break;
      const after = l.text === '-' ? '' : l.text.slice(2);
      const rest = after.trim();
      if (!rest) {
        pos++;
        arr.push(parseNode(indent + 1));
      } else if (KEY_RE.test(rest) && !rest.startsWith('"') && !rest.startsWith("'")) {
        const childIndent = indent + 2 + (after.length - after.trimStart().length);
        lines[pos] = { ...l, indent: childIndent, text: rest };
        arr.push(parseMap(childIndent));
      } else {
        pos++;
        arr.push(scalar(rest));
      }
    }
    return arr;
  }

  function parseMap(indent: number): Record<string, unknown> {
    const obj: Record<string, unknown> = {};
    for (;;) {
      skip();
      if (pos >= lines.length) break;
      const l = lines[pos];
      if (l.indent < indent) break;
      if (l.indent > indent) throw new YamlError('bad indentation of a mapping entry', l.no);
      if (isItem(l.text)) break;
      const m = KEY_RE.exec(l.text);
      if (!m) throw new YamlError("could not find expected ':' (implicit mapping key)", l.no);
      const key = String(scalar(m[1]));
      const val = (m[2] ?? '').trim();
      if (key in obj) throw new YamlError(`duplicated mapping key "${key}"`, l.no);
      pos++;
      if (val === '') {
        skip();
        const n = lines[pos];
        if (n && n.indent > indent) obj[key] = parseNode(n.indent);
        else if (n && n.indent === indent && isItem(n.text)) obj[key] = parseList(indent);
        else obj[key] = null;
      } else if (/^[|>][-+]?$/.test(val)) obj[key] = blockScalar(indent, val);
      else obj[key] = scalar(val);
    }
    return obj;
  }

  skip();
  if (pos >= lines.length) return null;
  const result = parseNode(lines[pos].indent);
  skip();
  if (pos < lines.length) throw new YamlError('unexpected content (check indentation)', lines[pos].no);
  return result;
}

/** Parse a multi-document YAML stream (separated by ---). */
export function parseYamlDocs(src: string): unknown[] {
  return src
    .split(/^---\s*$/m)
    .filter((d) => d.trim())
    .map((d) => parseYaml(d));
}
