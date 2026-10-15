import { useEffect, useState } from 'react';
import type { PipelineRun, StepStatus } from '../engine/types';
import { Ansi } from './Ansi';

const STEP_MS = 420;

function Status({ st }: { st: StepStatus | 'running' | 'invalid' }) {
  const ch = st === 'passed' ? '✓' : st === 'failed' || st === 'invalid' ? '✕' : st === 'warning' ? '!' : st === 'skipped' ? '–' : '';
  return <span className={`st ${st}`}>{ch}</span>;
}

interface Props {
  runs: PipelineRun[];
  animating: { id: number; start: number } | null;
  onViewFailedLog: () => void;
  workflowPath: string | null;
  onOpenWorkflow: () => void;
}

export function PipelineView({ runs, animating, onViewFailedLog, workflowPath, onOpenWorkflow }: Props) {
  const [sel, setSel] = useState<number | null>(null);
  const [job, setJob] = useState<string | null>(null);
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const [now, setNow] = useState(Date.now());
  const run = runs.find((r) => r.id === sel) ?? runs[runs.length - 1];

  useEffect(() => {
    if (animating) {
      setSel(animating.id);
      setJob(null);
    }
  }, [animating]);

  // reveal steps progressively while the newest run "executes"
  const flat = run ? run.jobs.flatMap((j) => j.steps.filter((s) => s.status !== 'skipped').map((s) => `${j.id}/${s.name}`)) : [];
  const anim = run && animating?.id === run.id;
  const revealed = anim ? Math.floor((now - animating!.start) / STEP_MS) : Infinity;
  useEffect(() => {
    if (!anim || revealed > flat.length) return;
    const t = setTimeout(() => setNow(Date.now()), STEP_MS / 2);
    return () => clearTimeout(t);
  }, [anim, revealed, flat.length, now]);

  if (!runs.length)
    return (
      <div className="findings" style={{ color: 'var(--muted)' }}>
        No pipeline runs yet. {workflowPath ? (
          <>
            Commit and <code>git push</code> to trigger <a href="#" onClick={(e) => (e.preventDefault(), onOpenWorkflow())}>{workflowPath}</a>.
          </>
        ) : (
          <>This repository has no workflow yet — create <code>.github/workflows/ci.yml</code> to add CI.</>
        )}
      </div>
    );

  const stepState = (jobId: string, name: string, st: StepStatus): StepStatus | 'running' => {
    if (!anim) return st;
    const i = flat.indexOf(`${jobId}/${name}`);
    if (i < 0) return st;
    if (i < revealed) return st;
    if (i === revealed) return 'running';
    return 'pending';
  };
  const jobState = (j: PipelineRun['jobs'][number]): StepStatus | 'running' => {
    if (!anim || j.status === 'skipped') return anim && revealed < flat.length ? (j.status === 'skipped' ? 'pending' : j.status) : j.status;
    const idx = j.steps.filter((s) => s.status !== 'skipped').map((s) => flat.indexOf(`${j.id}/${s.name}`));
    if (Math.max(...idx) < revealed) return j.status;
    if (Math.min(...idx) <= revealed) return 'running';
    return 'pending';
  };
  const runState = anim && revealed < flat.length ? 'running' : run.status;
  const curJob = run.jobs.find((j) => j.id === job) ?? run.jobs.find((j) => j.status === 'failed') ?? run.jobs[0];

  return (
    <div className="pipe">
      <div className="runs">
        {[...runs].reverse().map((r) => (
          <div key={r.id} className={`run ${r.id === run.id ? 'on' : ''}`} onClick={() => (setSel(r.id), setJob(null))}>
            <div className="l1">
              <Status st={animating?.id === r.id && revealed < flat.length ? 'running' : r.status} />
              <b>#{r.id}</b>
              <span style={{ color: 'var(--muted)' }}>ci · main</span>
            </div>
            <div className="l2">
              {r.commit.slice(0, 7)} {r.message}
            </div>
          </div>
        ))}
      </div>
      <div className="jobs">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
          <Status st={runState} />
          <b>
            Run #{run.id} — {runState === 'running' ? 'in progress' : run.status}
          </b>
          <span className="chip">{run.commit.slice(0, 7)}</span>
          <span style={{ color: 'var(--muted)' }}>{run.message}</span>
          {workflowPath && (
            <button className="btn sm ghost" style={{ marginLeft: 'auto' }} onClick={onOpenWorkflow}>
              Edit workflow
            </button>
          )}
        </div>
        {run.error ? (
          <div className="errorbox">{run.error}</div>
        ) : (
          <>
            <div className="jobgraph">
              {run.jobs.map((j, i) => (
                <span key={j.id} style={{ display: 'contents' }}>
                  {i > 0 && <span className="arrow">→</span>}
                  <span className={`jobnode ${curJob?.id === j.id ? 'on' : ''}`} onClick={() => setJob(j.id)} title={j.needs.length ? `needs: ${j.needs.join(', ')}` : 'no dependencies'}>
                    <Status st={jobState(j)} />
                    {j.name}
                    {j.needs.length > 0 && <span style={{ color: 'var(--dim)', fontSize: 11 }}>needs {j.needs.join(', ')}</span>}
                  </span>
                </span>
              ))}
            </div>
            {curJob?.steps.map((st, i) => {
              const key = `${run.id}/${curJob.id}/${i}`;
              const shown = stepState(curJob.id, st.name, st.status);
              const isOpen = open[key] ?? false;
              return (
                <div className="step" key={key}>
                  <div
                    className="sh"
                    onClick={() => {
                      setOpen((o) => ({ ...o, [key]: !isOpen }));
                      if (!isOpen && st.status === 'failed' && shown !== 'running' && shown !== 'pending') onViewFailedLog();
                    }}
                  >
                    <Status st={shown} />
                    <span>{st.name}</span>
                    <span className="ms">{shown === st.status && st.ms ? `${(st.ms / 1000).toFixed(1)}s` : ''}</span>
                  </div>
                  {isOpen && shown === st.status && st.log.length > 0 && (
                    <pre>
                      {st.log.map((l, k) => (
                        <div key={k}>
                          <Ansi text={l} />
                        </div>
                      ))}
                    </pre>
                  )}
                </div>
              );
            })}
          </>
        )}
      </div>
    </div>
  );
}
