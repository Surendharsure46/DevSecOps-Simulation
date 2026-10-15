import { useEffect, useRef } from 'react';
import type { Finding } from '../engine/types';

const SEV_COLOR: Record<string, string> = { CRITICAL: 'var(--crit)', HIGH: 'var(--high)', MEDIUM: 'var(--med)', LOW: 'var(--low)', INFO: 'var(--dim)' };

interface Props {
  path: string | null;
  value: string;
  onChange: (v: string) => void;
  findings: Finding[];
  status: string | null;
  jumpTo: { line: number; n: number } | null;
}

/** Lightweight code editor: textarea with line numbers and finding markers in the gutter. */
export function Editor({ path, value, onChange, findings, status, jumpTo }: Props) {
  const ta = useRef<HTMLTextAreaElement>(null);
  const body = useRef<HTMLDivElement>(null);
  const lines = value.split('\n');

  useEffect(() => {
    if (!jumpTo || !ta.current || !body.current) return;
    const idx = lines.slice(0, jumpTo.line - 1).join('\n').length + (jumpTo.line > 1 ? 1 : 0);
    ta.current.focus();
    ta.current.setSelectionRange(idx, idx + (lines[jumpTo.line - 1]?.length ?? 0));
    body.current.scrollTop = Math.max(0, (jumpTo.line - 6) * 20);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jumpTo]);

  if (!path) return <div className="editor"><div className="edhead">No file open</div><div className="empty">Select a file in the explorer</div></div>;

  const marks = new Map<number, Finding>();
  for (const f of findings) if (f.file === path && f.line && !marks.has(f.line)) marks.set(f.line, f);

  return (
    <div className="editor">
      <div className="edhead">
        <span style={{ color: 'var(--text)' }}>{path}</span>
        {status && <span className="chip amber" style={{ fontFamily: 'var(--sans)' }}>{status}</span>}
        <span className="spacer" />
        <span>{lines.length} lines · auto-saved</span>
      </div>
      <div className="edbody" ref={body}>
        <div className="gutter">
          {lines.map((_, i) => {
            const f = marks.get(i + 1);
            return (
              <div key={i} className={f ? 'flag' : ''} title={f ? `${f.severity} ${f.ruleId}: ${f.title}` : undefined} style={f ? ({ '--sevc': SEV_COLOR[f.severity] } as React.CSSProperties) : undefined}>
                {i + 1}
              </div>
            );
          })}
        </div>
        <textarea
          ref={ta}
          spellCheck={false}
          value={value}
          rows={lines.length + 2}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Tab') {
              e.preventDefault();
              const t = e.currentTarget;
              const { selectionStart: a, selectionEnd: b } = t;
              const next = value.slice(0, a) + '  ' + value.slice(b);
              onChange(next);
              requestAnimationFrame(() => t.setSelectionRange(a + 2, a + 2));
            }
          }}
        />
      </div>
    </div>
  );
}
