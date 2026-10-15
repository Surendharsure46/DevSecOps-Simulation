import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { LabDef, Mode } from '../engine/lab';
import { createLabState, score, settle } from '../engine/lab';
import type { LabState } from '../engine/types';
import { runLine, type ShellCtx } from '../engine/shell';
import { ancestry, status } from '../engine/git';
import { findWorkflow } from '../engine/pipeline';
import { revOf } from '../engine/shell';
import { clearLabState, loadLabState, saveLabState, type Progress } from '../store';
import { LABS } from '../content/labs';
import { isUnlocked } from './Dashboard';
import { Editor } from '../components/Editor';
import { FileTree } from '../components/FileTree';
import { Terminal, type TerminalHandle } from '../components/Terminal';
import { Findings } from '../components/Findings';
import { PipelineView } from '../components/PipelineView';
import { TaskPanel } from '../components/TaskPanel';
import { Ansi } from '../components/Ansi';

type Tab = 'terminal' | 'findings' | 'pipeline' | 'git' | 'activity';

interface Props {
  def: LabDef;
  mode: Mode;
  progress: Progress;
  update: (fn: (p: Progress) => Progress) => void;
  go: (r: string) => void;
}

function fmtTime(ms: number) {
  const s = Math.max(0, Math.floor(ms / 1000));
  return `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;
}

export function LabPage({ def, mode, progress, update, go }: Props) {
  const stateRef = useRef<LabState>(loadLabState(def.id) ?? createLabState(def));
  const s = stateRef.current;
  const [, setTick] = useState(0);
  const [termKey, setTermKey] = useState(0);
  const [active, setActive] = useState<string | null>(s.files[def.openFile] !== undefined ? def.openFile : Object.keys(s.files)[0] ?? null);
  const [tab, setTab] = useState<Tab>('terminal');
  const [toasts, setToasts] = useState<{ id: number; text: string }[]>([]);
  const [animating, setAnimating] = useState<{ id: number; start: number } | null>(null);
  const [jump, setJump] = useState<{ line: number; n: number } | null>(null);
  const [showCommit, setShowCommit] = useState(false);
  const [showDone, setShowDone] = useState(false);
  const [bottomPct, setBottomPct] = useState(42);
  const [now, setNow] = useState(Date.now());
  const term = useRef<TerminalHandle>(null);
  const env = useRef<Record<string, string>>({ HOME: '/home/devsecops', USER: 'devsecops', NODE_ENV: 'development' });
  const settleTimer = useRef<number | undefined>(undefined);

  const toast = useCallback((text: string) => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, text }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 4200);
  }, []);

  const finish = useCallback(
    (st: LabState) => {
      const sc = score(def, st, mode);
      const minutes = Math.round(((st.completedAt ?? Date.now()) - st.startedAt) / 60000);
      update((p) => {
        const prev = p.results[def.id];
        if (prev && prev.score >= sc.score) return p;
        return { ...p, results: { ...p.results, [def.id]: { score: sc.score, max: sc.max, mode, minutes, completedAt: st.completedAt ?? Date.now() } } };
      });
      setShowDone(true);
    },
    [def, mode, update],
  );

  /** Re-evaluate the lab after any action. */
  const afterAction = useCallback(() => {
    const st = stateRef.current;
    const wasComplete = !!st.completedAt;
    const { newlyAchieved, run } = settle(def, st);
    for (const id of newlyAchieved) {
      const o = def.objectives.find((x) => x.id === id)!;
      toast(`✔ ${o.bonus ? 'Bonus' : 'Objective'} complete: ${o.title}`);
    }
    if (run) {
      setAnimating({ id: run.id, start: Date.now() });
      toast(`Pipeline #${run.id} started for ${run.commit.slice(0, 7)} — see the Pipeline tab`);
    }
    saveLabState(st);
    setTick((t) => t + 1);
    if (!wasComplete && st.completedAt) setTimeout(() => finish(st), run ? 2500 : 600);
  }, [def, finish, toast]);

  const execute = useCallback(
    (cmd: string) => {
      const st = stateRef.current;
      const ctx: ShellCtx = { s: st, fs: st.files, installed: st.installed, pipeline: false, env: env.current, flags: st.flags, tests: def.tests, commit: st.head };
      const r = runLine(cmd, ctx);
      st.activity.push({ t: Date.now(), kind: /^git /.test(cmd) ? 'git' : 'cmd', text: `$ ${cmd}${r.code ? `  (exit ${r.code})` : ''}` });
      if (st.activity.length > 400) st.activity.splice(0, st.activity.length - 400);
      if (active && st.files[active] === undefined) setActive(Object.keys(st.files).find((f) => f === def.openFile) ?? Object.keys(st.files)[0] ?? null);
      afterAction();
      return r;
    },
    [active, afterAction, def],
  );

  useEffect(() => {
    if (s.completedAt) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [s.completedAt]);

  useEffect(() => {
    afterAction();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const onEdit = (v: string) => {
    if (!active) return;
    s.files[active] = v;
    setTick((t) => t + 1);
    window.clearTimeout(settleTimer.current);
    settleTimer.current = window.setTimeout(() => {
      s.activity.push({ t: Date.now(), kind: 'edit', text: `edited ${active}` });
      afterAction();
    }, 450);
  };

  const gitMarks = useMemo(() => {
    const m: Record<string, string> = {};
    for (const e of status(s)) m[e.path] = e.untracked || e.staged === 'A' ? 'U' : 'M';
    return m;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [s, s.files, s.index, s.head, s.activity.length, now]);

  const rev = revOf(s);
  const currentFindings = Object.values(s.scans).flatMap((r) => (r!.rev === rev ? r!.findings : []));
  const findingsByFile: Record<string, number> = {};
  for (const f of currentFindings) if (f.file && s.files[f.file] !== undefined) findingsByFile[f.file] = (findingsByFile[f.file] ?? 0) + 1;
  const allFindings = Object.values(s.scans).flatMap((r) => r!.findings);
  const lastRun = s.pipelineRuns[s.pipelineRuns.length - 1];
  const wf = findWorkflow(s.files);
  const req = def.objectives.filter((o) => !o.bonus);
  const doneN = req.filter((o) => s.achieved.includes(o.id)).length;
  const headDiff = active ? (ancestry(s.commits, s.head)[0]?.files[active] === s.files[active] ? null : ancestry(s.commits, s.head)[0]?.files[active] === undefined ? 'new' : 'modified') : null;

  if (!isUnlocked(def.id, progress))
    return (
      <div className="page">
        <div className="wrap section">
          <h2>🔒 {def.title} is locked</h2>
          <p className="sub">Complete the previous lab first, or switch to Expert mode on the dashboard to unlock everything.</p>
          <button className="btn primary" onClick={() => go('/labs')}>
            Back to my labs
          </button>
        </div>
      </div>
    );

  const startDrag = (e: React.MouseEvent) => {
    e.preventDefault();
    const h = window.innerHeight;
    const move = (ev: MouseEvent) => setBottomPct(Math.min(80, Math.max(15, ((h - ev.clientY) / (h - 48)) * 100)));
    const up = () => {
      window.removeEventListener('mousemove', move);
      window.removeEventListener('mouseup', up);
    };
    window.addEventListener('mousemove', move);
    window.addEventListener('mouseup', up);
  };

  const idx = LABS.findIndex((l) => l.id === def.id);
  const nextLab = LABS[idx + 1];
  const sc = score(def, s, mode);

  return (
    <div className="ws">
      <header className="wsbar">
        <button className="btn ghost sm" onClick={() => go('/labs')}>
          ← Labs
        </button>
        <span className="chip">L{def.level}</span>
        <span className="title">{def.title}</span>
        <span className={`chip ${mode === 'guided' ? 'green' : mode === 'standard' ? 'blue' : 'violet'}`}>{mode}</span>
        <span className="spacer" />
        <span className="chip green">
          {doneN}/{req.length} objectives
        </span>
        <span className="timer" title="Time in lab">
          ⏱ {fmtTime((s.completedAt ?? now) - s.startedAt)}
          {mode === 'expert' ? ` / ${def.minutes}:00` : ''}
        </span>
        <button className="btn sm" onClick={() => setShowCommit(true)}>
          ⎇ Commit &amp; Push
        </button>
        {s.completedAt && (
          <button className="btn sm primary" onClick={() => setShowDone(true)}>
            Results
          </button>
        )}
        <button
          className="btn sm ghost"
          title="Reset this lab to its starting state"
          onClick={() => {
            if (!window.confirm('Reset this lab? Your changes, scans and pipeline runs in this lab will be discarded.')) return;
            clearLabState(def.id);
            stateRef.current = createLabState(def);
            setActive(def.openFile);
            setTermKey((k) => k + 1);
            setAnimating(null);
            afterAction();
          }}
        >
          ↺ Reset
        </button>
      </header>

      <div className="wsmain">
        <TaskPanel
          def={def}
          s={s}
          mode={mode}
          onRun={(c) => {
            setTab('terminal');
            setTimeout(() => term.current?.run(c), 0);
          }}
          onPaste={(c) => {
            setTab('terminal');
            setTimeout(() => term.current?.insert(c), 0);
          }}
          onHint={(key) => {
            if (!s.hintsUsed.includes(key)) s.hintsUsed.push(key);
            s.activity.push({ t: Date.now(), kind: 'hint', text: `hint used (${key})` });
            afterAction();
          }}
        />

        <section className="center" style={{ '--bottom': `${bottomPct}%` } as React.CSSProperties}>
          <div className="editorarea">
            <FileTree
              files={Object.keys(s.files)}
              active={active}
              marks={gitMarks}
              findingsByFile={findingsByFile}
              onOpen={setActive}
              onNew={() => {
                const p = window.prompt('New file path (e.g. .dockerignore or .github/workflows/ci.yml)');
                if (!p) return;
                const path = p.replace(/^\.?\//, '');
                if (s.files[path] === undefined) s.files[path] = '';
                setActive(path);
                afterAction();
              }}
              onDelete={(p) => {
                delete s.files[p];
                if (active === p) setActive(def.openFile);
                afterAction();
              }}
            />
            <Editor path={active && s.files[active] !== undefined ? active : null} value={active ? (s.files[active] ?? '') : ''} onChange={onEdit} findings={currentFindings} status={headDiff} jumpTo={jump} />
          </div>
          <div className="splitter" onMouseDown={startDrag} title="Drag to resize" />
          <div className="bottom">
            <div className="tabs">
              <button className={tab === 'terminal' ? 'on' : ''} onClick={() => setTab('terminal')}>
                Terminal
              </button>
              <button className={tab === 'findings' ? 'on' : ''} onClick={() => setTab('findings')}>
                Findings {allFindings.length > 0 && <span className="badge red">{allFindings.length}</span>}
              </button>
              <button className={tab === 'pipeline' ? 'on' : ''} onClick={() => setTab('pipeline')}>
                Pipeline {lastRun && <span className={`badge ${lastRun.status === 'passed' ? 'green' : 'red'}`}>#{lastRun.id} {lastRun.status}</span>}
              </button>
              <button className={tab === 'git' ? 'on' : ''} onClick={() => setTab('git')}>
                Git {Object.keys(gitMarks).length > 0 && <span className="badge">{Object.keys(gitMarks).length}</span>}
              </button>
              <button className={tab === 'activity' ? 'on' : ''} onClick={() => setTab('activity')}>
                Activity
              </button>
            </div>
            <div className="tabbody">
              <div style={{ display: tab === 'terminal' ? 'block' : 'none', height: '100%' }}>
                <Terminal
                  key={termKey}
                  ref={term}
                  execute={execute}
                  files={Object.keys(s.files)}
                  initial={[
                    `\x1b[1mShopFlow DevSecOps workstation\x1b[0m — lab: ${def.title}`,
                    `\x1b[90mRepository cloned to /workspace/shopflow-api · type \x1b[0mhelp\x1b[90m for available tools · ↑/↓ history · Tab completion\x1b[0m`,
                    '',
                  ]}
                />
              </div>
              {tab === 'findings' && (
                <Findings
                  s={s}
                  onJump={(file, line) => {
                    setActive(file);
                    setJump({ line, n: Date.now() });
                  }}
                />
              )}
              {tab === 'pipeline' && (
                <PipelineView
                  runs={s.pipelineRuns}
                  animating={animating}
                  workflowPath={wf}
                  onOpenWorkflow={() => wf && setActive(wf)}
                  onViewFailedLog={() => {
                    if (!s.flags.viewedFailedLog) {
                      s.flags.viewedFailedLog = true;
                      afterAction();
                    }
                  }}
                />
              )}
              {tab === 'git' && <GitPanel s={s} onOpen={setActive} />}
              {tab === 'activity' && (
                <div className="activity">
                  {[...s.activity].reverse().map((a, i) => (
                    <div key={i}>
                      <time>{new Date(a.t).toLocaleTimeString()}</time>
                      <span style={{ color: a.kind === 'objective' ? 'var(--accent)' : a.kind === 'pipeline' ? 'var(--blue)' : a.kind === 'hint' ? 'var(--amber)' : undefined }}>{a.text}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </section>
      </div>

      {showCommit && (
        <CommitDialog
          s={s}
          onClose={() => setShowCommit(false)}
          onCommit={(msg, push) => {
            setShowCommit(false);
            setTab('terminal');
            const safe = msg.replace(/"/g, "'");
            setTimeout(() => term.current?.run(`git add -A && git commit -m "${safe}"${push ? ' && git push' : ''}`), 0);
          }}
        />
      )}

      {showDone && (
        <div className="modalbg" onClick={() => setShowDone(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <span className="chip green">Lab complete</span>
            <h2 style={{ marginTop: 10 }}>{def.title}</h2>
            <div style={{ display: 'flex', gap: 24, alignItems: 'baseline', margin: '10px 0' }}>
              <div>
                <div className="big">{sc.score}</div>
                <div style={{ color: 'var(--muted)', fontSize: 12.5 }}>points (max {sc.max})</div>
              </div>
              <div style={{ color: 'var(--muted)', fontSize: 13.5 }}>
                ⏱ {fmtTime((s.completedAt ?? Date.now()) - s.startedAt)} · {mode} mode
                <br />
                {s.hintsUsed.length} hint(s) · {s.pipelineRuns.length} pipeline run(s) · {s.activity.filter((a) => a.kind === 'cmd' || a.kind === 'git').length} commands
              </div>
            </div>
            {def.objectives.map((o) => (
              <div key={o.id} style={{ fontSize: 13.5, padding: '2px 0', color: s.achieved.includes(o.id) ? 'var(--text)' : 'var(--dim)' }}>
                {s.achieved.includes(o.id) ? '✅' : '⬜'} {o.title} {o.bonus ? '(bonus)' : ''}
              </div>
            ))}
            <p style={{ color: 'var(--muted)', fontSize: 13, marginTop: 12 }}>Skills practised: {def.skills.join(', ')}.</p>
            <div className="actions">
              <button className="btn" onClick={() => downloadReport(def, s, mode)}>
                ⬇ Download report
              </button>
              <button className="btn" onClick={() => setShowDone(false)}>
                Keep exploring
              </button>
              {nextLab ? (
                <button className="btn primary" onClick={() => go(`/lab/${nextLab.id}`)}>
                  Next: {nextLab.title} →
                </button>
              ) : (
                <button className="btn primary" onClick={() => go('/labs')}>
                  Back to labs
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      <div className="toast">
        {toasts.map((t) => (
          <div key={t.id}>{t.text}</div>
        ))}
      </div>
    </div>
  );
}

function GitPanel({ s, onOpen }: { s: LabState; onOpen: (p: string) => void }) {
  const st = status(s);
  const log = ancestry(s.commits, s.head);
  return (
    <div className="findings">
      <div className="scanhdr">
        <b>Branch main</b>
        <span className="chip">{s.remote.url ? `origin: ${s.remote.url}` : 'no remote configured'}</span>
        <span className={s.remote.head === s.head ? 'fresh' : 'stale'}>{s.remote.head === s.head ? '● in sync with origin/main' : '● local commits not pushed'}</span>
      </div>
      {st.length === 0 ? (
        <p style={{ color: 'var(--muted)' }}>Working tree clean.</p>
      ) : (
        st.map((e) => (
          <div key={e.path} style={{ fontFamily: 'var(--mono)', fontSize: 12.5, cursor: 'pointer' }} onClick={() => s.files[e.path] !== undefined && onOpen(e.path)}>
            <span style={{ color: e.staged ? 'var(--accent)' : 'var(--high)', display: 'inline-block', width: 90 }}>{e.untracked ? 'untracked' : e.staged ? `staged ${e.staged}` : `modified`}</span>
            {e.path}
          </div>
        ))
      )}
      <div className="scanhdr" style={{ marginTop: 16 }}>
        <b>History</b>
      </div>
      {log.map((c) => (
        <div key={c.id} style={{ fontFamily: 'var(--mono)', fontSize: 12.5, padding: '2px 0' }}>
          <Ansi text={`\x1b[33m${c.id.slice(0, 7)}\x1b[0m ${c.id === s.remote.head ? '\x1b[36m(origin/main) \x1b[0m' : ''}${c.message} \x1b[90m— ${c.author.split(' <')[0]}, ${new Date(c.date).toLocaleDateString()}\x1b[0m`} />
        </div>
      ))}
    </div>
  );
}

function CommitDialog({ s, onClose, onCommit }: { s: LabState; onClose: () => void; onCommit: (msg: string, push: boolean) => void }) {
  const [msg, setMsg] = useState('');
  const [push, setPush] = useState(true);
  const st = status(s);
  return (
    <div className="modalbg" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h2>Commit &amp; Push</h2>
        <p style={{ color: 'var(--muted)', fontSize: 13.5, margin: '4px 0' }}>Runs <code>git add -A</code>, <code>git commit</code> and optionally <code>git push</code> in the terminal so you can see exactly what happens. Files listed in .gitignore are not added.</p>
        <div className="changes">
          {st.length ? st.map((e) => <div key={e.path}>{e.untracked ? 'A' : e.unstaged ?? e.staged} {e.path}</div>) : <div style={{ color: 'var(--dim)' }}>No changes — nothing to commit.</div>}
        </div>
        <input type="text" placeholder="Commit message, e.g. Fix SQL injection in orders route" value={msg} autoFocus onChange={(e) => setMsg(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && msg.trim() && onCommit(msg.trim(), push)} />
        <label style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 10, fontSize: 13.5 }}>
          <input type="checkbox" checked={push} onChange={(e) => setPush(e.target.checked)} /> Push to origin/main (triggers the CI pipeline)
        </label>
        <div className="actions">
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button className="btn primary" disabled={!msg.trim()} onClick={() => onCommit(msg.trim(), push)}>
            Commit{push ? ' & Push' : ''}
          </button>
        </div>
      </div>
    </div>
  );
}

function downloadReport(def: LabDef, s: LabState, mode: Mode) {
  const sc = score(def, s, mode);
  const strip = (t: string) => t.replace(/\x1b\[[0-9;]*m/g, '');
  const md = [
    `# Lab report — ${def.title}`,
    '',
    `- Mode: ${mode}`,
    `- Score: ${sc.score} / ${sc.max}`,
    `- Time: ${fmtTime((s.completedAt ?? Date.now()) - s.startedAt)}`,
    `- Hints used: ${s.hintsUsed.length}`,
    `- Pipeline runs: ${s.pipelineRuns.map((r) => `#${r.id} ${r.status}`).join(', ') || 'none'}`,
    '',
    '## Objectives',
    ...def.objectives.map((o) => `- [${s.achieved.includes(o.id) ? 'x' : ' '}] ${o.title}${o.bonus ? ' (bonus)' : ''}`),
    '',
    '## Latest scan results',
    ...Object.values(s.scans).map((r) => `- ${r!.tool} on ${r!.target}: ${r!.findings.length} finding(s)`),
    '',
    '## Activity log',
    ...s.activity.map((a) => `- ${new Date(a.t).toLocaleTimeString()} ${strip(a.text)}`),
    '',
  ].join('\n');
  const url = URL.createObjectURL(new Blob([md], { type: 'text/markdown' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = `${def.id}-report.md`;
  a.click();
  URL.revokeObjectURL(url);
}
