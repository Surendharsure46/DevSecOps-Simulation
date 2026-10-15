import type { LabState, ScanRecord, ToolName } from '../engine/types';
import { TOOL_LABEL } from '../engine/types';
import { revOf } from '../engine/shell';

const ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

export function openFindings(s: LabState) {
  return Object.values(s.scans).flatMap((r) => (r as ScanRecord).findings);
}

export function Findings({ s, onJump }: { s: LabState; onJump: (file: string, line: number) => void }) {
  const scans = Object.values(s.scans) as ScanRecord[];
  if (!scans.length)
    return (
      <div className="findings" style={{ color: 'var(--muted)' }}>
        No scans yet. Run a scanner in the Terminal (e.g. <code>gitleaks git -v</code>, <code>semgrep scan --config auto</code>, <code>trivy fs .</code>) — results appear here, grouped by tool, with links to the exact line.
      </div>
    );
  const rev = revOf(s);
  return (
    <div className="findings">
      {scans
        .sort((a, b) => b.at - a.at)
        .map((r) => (
          <div key={r.tool}>
            <div className="scanhdr">
              <b>{TOOL_LABEL[r.tool as ToolName]}</b>
              <span className="chip">{r.target}</span>
              <span className="chip">{new Date(r.at).toLocaleTimeString()}</span>
              {r.rev === rev ? <span className="fresh">● current code</span> : <span className="stale">● stale — code changed since this scan, re-run to verify</span>}
              <span style={{ marginLeft: 'auto', color: r.findings.length ? 'var(--high)' : 'var(--accent)', fontSize: 12.5 }}>{r.findings.length ? `${r.findings.length} finding${r.findings.length > 1 ? 's' : ''}` : 'clean ✓'}</span>
            </div>
            {[...r.findings]
              .sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity))
              .map((f, i) => (
                <div className="finding" key={i}>
                  <div>
                    <span className={`sev ${f.severity}`}>{f.severity}</span>
                  </div>
                  <div>
                    <div className="rule">
                      {f.ruleId}
                      {f.pkg ? ` · ${f.pkg} ${f.installed} → ${f.fixed}` : ''}
                    </div>
                    <div className="ttl">{f.title}</div>
                    {f.detail && <div className="rule" style={{ marginTop: 2 }}>{f.detail}</div>}
                    {f.remediation && <div className="rem">↳ {f.remediation}</div>}
                  </div>
                  <div>
                    {f.file && f.line && s.files[f.file] !== undefined ? (
                      <span className="loc" onClick={() => onJump(f.file!, f.line!)}>
                        {f.file}:{f.line}
                      </span>
                    ) : (
                      <span className="rule">{f.url ?? f.file ?? ''}</span>
                    )}
                  </div>
                </div>
              ))}
          </div>
        ))}
    </div>
  );
}
