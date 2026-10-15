import type { LabDef } from '../../engine/lab';
import { redBuild } from './l0-red-build';
import { secretsLab } from './l1-secrets';
import { sastLab } from './l2-sast';
import { scaLab } from './l3-sca';
import { containerLab } from './l4-container';
import { iacLab } from './l5-iac';
import { pipelineLab } from './l6-pipeline-gate';
import { capstoneLab } from './l7-capstone';

export const LABS: LabDef[] = [redBuild, secretsLab, sastLab, scaLab, containerLab, iacLab, pipelineLab, capstoneLab];

export const LEVELS = [
  { level: 0, name: 'Foundations', blurb: 'Git, CI pipelines and tests as gates' },
  { level: 1, name: 'Shift-left basics', blurb: 'Secrets and static analysis' },
  { level: 2, name: 'Build security', blurb: 'Dependencies, SBOMs and container images' },
  { level: 3, name: 'Platform security', blurb: 'Infrastructure as code and pipeline gates' },
  { level: 4, name: 'Professional', blurb: 'End-to-end secure release' },
];

export const labById = (id: string) => LABS.find((l) => l.id === id);
