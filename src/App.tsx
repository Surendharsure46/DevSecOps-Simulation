import { useCallback, useEffect, useState } from 'react';
import { loadProgress, saveProgress, type Progress } from './store';
import { Welcome } from './pages/Welcome';
import { GetStarted } from './pages/GetStarted';
import { Dashboard } from './pages/Dashboard';
import { LabPage } from './pages/LabPage';
import { labById } from './content/labs';

function useHashRoute(): [string, (r: string) => void] {
  const [route, setRoute] = useState(() => window.location.hash.replace(/^#/, '') || '/');
  useEffect(() => {
    const on = () => setRoute(window.location.hash.replace(/^#/, '') || '/');
    window.addEventListener('hashchange', on);
    return () => window.removeEventListener('hashchange', on);
  }, []);
  const go = useCallback((r: string) => {
    window.location.hash = r;
    window.scrollTo(0, 0);
  }, []);
  return [route, go];
}

export function App() {
  const [route, go] = useHashRoute();
  const [progress, setProgress] = useState<Progress>(loadProgress);
  const update = useCallback((fn: (p: Progress) => Progress) => {
    setProgress((p) => {
      const next = fn(p);
      saveProgress(next);
      return next;
    });
  }, []);

  if (route === '/start') return <GetStarted progress={progress} update={update} go={go} />;
  if (route === '/labs') return progress.mode ? <Dashboard progress={progress} update={update} go={go} /> : <GetStarted progress={progress} update={update} go={go} />;
  const m = /^\/lab\/([\w-]+)$/.exec(route);
  if (m) {
    const def = labById(m[1]);
    if (def && progress.mode) return <LabPage key={def.id} def={def} mode={progress.mode} progress={progress} update={update} go={go} />;
  }
  return <Welcome go={go} hasProgress={!!progress.mode} />;
}
