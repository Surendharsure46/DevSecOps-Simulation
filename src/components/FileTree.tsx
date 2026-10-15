import { useMemo, useState } from 'react';

interface Props {
  files: string[];
  active: string | null;
  marks: Record<string, string>;
  findingsByFile: Record<string, number>;
  onOpen: (p: string) => void;
  onNew: () => void;
  onDelete: (p: string) => void;
}

interface Node {
  name: string;
  path: string;
  children: Node[];
  file: boolean;
}

function build(paths: string[]): Node[] {
  const root: Node = { name: '', path: '', children: [], file: false };
  for (const p of paths.sort()) {
    let cur = root;
    const parts = p.split('/');
    parts.forEach((seg, i) => {
      const path = parts.slice(0, i + 1).join('/');
      let n = cur.children.find((c) => c.name === seg);
      if (!n) {
        n = { name: seg, path, children: [], file: i === parts.length - 1 };
        cur.children.push(n);
      }
      cur = n;
    });
  }
  const sort = (ns: Node[]) => {
    ns.sort((a, b) => (a.file === b.file ? a.name.localeCompare(b.name) : a.file ? 1 : -1));
    ns.forEach((n) => sort(n.children));
  };
  sort(root.children);
  return root.children;
}

export function FileTree({ files, active, marks, findingsByFile, onOpen, onNew, onDelete }: Props) {
  const tree = useMemo(() => build([...files]), [files]);
  const [closed, setClosed] = useState<Record<string, boolean>>({});
  const render = (ns: Node[], depth: number) =>
    ns.map((n) =>
      n.file ? (
        <div
          key={n.path}
          className={`item ${active === n.path ? 'on' : ''}`}
          style={{ paddingLeft: 10 + depth * 14 }}
          onClick={() => onOpen(n.path)}
          onContextMenu={(e) => {
            e.preventDefault();
            if (window.confirm(`Delete ${n.path}?`)) onDelete(n.path);
          }}
          title={n.path}
        >
          <span>📄</span>
          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{n.name}</span>
          {findingsByFile[n.path] ? <span className="mark F">●{findingsByFile[n.path]}</span> : marks[n.path] ? <span className={`mark ${marks[n.path]}`}>{marks[n.path]}</span> : null}
        </div>
      ) : (
        <div key={n.path}>
          <div className="item dir" style={{ paddingLeft: 10 + depth * 14 }} onClick={() => setClosed((c) => ({ ...c, [n.path]: !c[n.path] }))}>
            <span>{closed[n.path] ? '▸' : '▾'}</span>
            <span>{n.name}</span>
          </div>
          {!closed[n.path] && render(n.children, depth + 1)}
        </div>
      ),
    );
  return (
    <div className="tree">
      <div className="hdr">
        <span>Explorer · shopflow-api</span>
        <button className="btn ghost sm" title="New file" onClick={onNew}>
          ＋
        </button>
      </div>
      {render(tree, 0)}
    </div>
  );
}
