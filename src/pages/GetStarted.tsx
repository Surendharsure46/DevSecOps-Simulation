import { useState } from 'react';
import type { Mode } from '../engine/lab';
import type { Progress } from '../store';
import { Brand } from '../components/Brand';

const MODES: { id: Mode; label: string; who: string; chip: string; points: string[] }[] = [
  {
    id: 'guided',
    label: 'Guided',
    who: 'Fresher / career switcher',
    chip: 'green',
    points: ['Step-by-step guidance for every objective', 'One-click example commands', 'Free, progressive hints', 'Key concepts explained in context', 'Levels unlock in order'],
  },
  {
    id: 'standard',
    label: 'Standard',
    who: 'Developer / junior engineer',
    chip: 'blue',
    points: ['Objectives and story, no walkthrough', 'Hints available (−5 points each)', 'You choose commands and fixes', 'Levels unlock in order'],
  },
  {
    id: 'expert',
    label: 'Expert',
    who: 'Experienced DevSecOps / security engineer',
    chip: 'violet',
    points: ['Only the ticket and acceptance criteria', 'No hints, timer with speed bonus', 'Troubleshooting traps left in place', 'All labs unlocked from the start'],
  },
];

export function GetStarted({ progress, update, go }: { progress: Progress; update: (fn: (p: Progress) => Progress) => void; go: (r: string) => void }) {
  const [mode, setMode] = useState<Mode>(progress.mode ?? 'guided');
  return (
    <div className="page">
      <nav className="topnav">
        <Brand onClick={() => go('/')} />
        <button className="btn ghost" onClick={() => go('/')}>
          ← Back
        </button>
      </nav>
      <div className="wrap section">
        <span className="chip">Step 1 of 1</span>
        <h2 style={{ marginTop: 12 }}>How do you want to work?</h2>
        <p className="sub">
          You are joining ShopFlow&apos;s platform team. Every lab gives you a repository, a terminal, a CI pipeline and a staging cluster. Choose the level of support
          that fits you — you can change it later from the lab dashboard.
        </p>
        <div className="modes">
          {MODES.map((m) => (
            <button key={m.id} className={`mode ${mode === m.id ? 'on' : ''}`} onClick={() => setMode(m.id)}>
              <span className={`chip ${m.chip}`}>{m.label}</span>
              <h3>{m.label} mode</h3>
              <div className="who">{m.who}</div>
              <ul>
                {m.points.map((p) => (
                  <li key={p}>{p}</li>
                ))}
              </ul>
            </button>
          ))}
        </div>
        <div style={{ marginTop: 28, display: 'flex', gap: 12 }}>
          <button
            className="btn primary"
            onClick={() => {
              update((p) => ({ ...p, mode }));
              go('/labs');
            }}
          >
            Continue to my labs →
          </button>
        </div>
      </div>
    </div>
  );
}
