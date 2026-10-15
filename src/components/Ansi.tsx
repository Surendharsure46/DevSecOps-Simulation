/** Render a line containing ANSI SGR colour codes as styled spans. */
export function Ansi({ text }: { text: string }) {
  const parts = text.split(/(\x1b\[[0-9;]*m)/);
  let bold = false;
  let color = '';
  return (
    <>
      {parts.map((p, i) => {
        const m = /^\x1b\[([0-9;]*)m$/.exec(p);
        if (m) {
          for (const code of m[1].split(';')) {
            if (code === '0' || code === '') {
              bold = false;
              color = '';
            } else if (code === '1') bold = true;
            else color = `a${code}`;
          }
          return null;
        }
        return p ? (
          <span key={i} className={`${color}${bold ? ' a1' : ''}`}>
            {p}
          </span>
        ) : null;
      })}
    </>
  );
}
