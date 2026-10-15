import type { LabState } from './engine/types';
import type { Mode } from './engine/lab';

// Per-browser progress (no login): chosen mode, saved lab workspaces and results.

export interface LabResult {
  score: number;
  max: number;
  mode: Mode;
  minutes: number;
  completedAt: number;
}

export interface Progress {
  mode: Mode | null;
  results: Record<string, LabResult>;
}

const KEY = 'devsecops-lab:progress:v1';
const LAB_KEY = (id: string) => `devsecops-lab:state:v1:${id}`;

export function loadProgress(): Progress {
  try {
    const raw = localStorage.getItem(KEY);
    if (raw) return { mode: null, results: {}, ...(JSON.parse(raw) as Partial<Progress>) };
  } catch {
    /* storage unavailable */
  }
  return { mode: null, results: {} };
}

export function saveProgress(p: Progress) {
  try {
    localStorage.setItem(KEY, JSON.stringify(p));
  } catch {
    /* storage unavailable */
  }
}

export function loadLabState(id: string): LabState | null {
  try {
    const raw = localStorage.getItem(LAB_KEY(id));
    return raw ? (JSON.parse(raw) as LabState) : null;
  } catch {
    return null;
  }
}

export function saveLabState(s: LabState) {
  try {
    localStorage.setItem(LAB_KEY(s.labId), JSON.stringify(s));
  } catch {
    // quota exceeded: drop bulky pipeline logs and retry once
    try {
      const slim = { ...s, pipelineRuns: s.pipelineRuns.slice(-5) };
      localStorage.setItem(LAB_KEY(s.labId), JSON.stringify(slim));
    } catch {
      /* give up silently; progress still lives in memory */
    }
  }
}

export function clearLabState(id: string) {
  try {
    localStorage.removeItem(LAB_KEY(id));
  } catch {
    /* ignore */
  }
}

export function resetAll() {
  try {
    Object.keys(localStorage)
      .filter((k) => k.startsWith('devsecops-lab:'))
      .forEach((k) => localStorage.removeItem(k));
  } catch {
    /* ignore */
  }
}
