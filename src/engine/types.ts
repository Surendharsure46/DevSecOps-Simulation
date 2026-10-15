export type Files = Record<string, string>;

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type ToolName =
  | 'gitleaks'
  | 'semgrep'
  | 'trivy-fs'
  | 'npm-audit'
  | 'hadolint'
  | 'trivy-config'
  | 'trivy-image'
  | 'checkov'
  | 'kyverno'
  | 'zap';

export const TOOL_LABEL: Record<ToolName, string> = {
  gitleaks: 'Gitleaks · secrets',
  semgrep: 'Semgrep · SAST',
  'trivy-fs': 'Trivy fs · SCA',
  'npm-audit': 'npm audit · SCA',
  hadolint: 'Hadolint · Dockerfile',
  'trivy-config': 'Trivy config · misconfig',
  'trivy-image': 'Trivy image',
  checkov: 'Checkov · IaC',
  kyverno: 'Kyverno · admission',
  zap: 'OWASP ZAP · DAST',
};

export interface Finding {
  tool: ToolName;
  ruleId: string;
  severity: Severity;
  title: string;
  file?: string;
  line?: number;
  detail?: string;
  remediation?: string;
  pkg?: string;
  installed?: string;
  fixed?: string;
  url?: string;
}

export interface Commit {
  id: string;
  parent: string | null;
  message: string;
  author: string;
  date: string;
  files: Files;
}

export interface IamKey {
  id: string;
  user: string;
  status: 'Active' | 'Inactive';
  created: string;
}

export interface ImageInfo {
  tag: string;
  base: string;
  user: string;
  env: Record<string, string>;
  cmd: string;
  shellForm: boolean;
  healthcheck: boolean;
  packages: string[];
  hasEnvFile: boolean;
  hasGitDir: boolean;
  sizeMb: number;
  files: Files;
  installed: Record<string, string>;
  users: string[];
  entrypoint: string | null;
  family: string;
}

export interface Deployment {
  image: string;
  commit: string;
  files: Files;
  installed: Record<string, string>;
  at: number;
}

export type StepStatus = 'pending' | 'passed' | 'failed' | 'skipped' | 'warning';

export interface PipelineStep {
  name: string;
  status: StepStatus;
  log: string[];
  ms: number;
}

export interface PipelineJob {
  id: string;
  name: string;
  needs: string[];
  status: StepStatus;
  steps: PipelineStep[];
}

export interface PipelineRun {
  id: number;
  commit: string;
  message: string;
  status: 'passed' | 'failed' | 'invalid';
  error?: string;
  jobs: PipelineJob[];
  at: number;
  /** tools whose step actually executed, with exit codes */
  toolExits: Record<string, number>;
}

export interface ScanRecord {
  tool: ToolName;
  rev: string;
  findings: Finding[];
  at: number;
  target: string;
}

export interface Activity {
  t: number;
  kind: 'cmd' | 'edit' | 'git' | 'pipeline' | 'hint' | 'objective' | 'system';
  text: string;
}

export interface LabState {
  labId: string;
  files: Files;
  index: Files;
  commits: Commit[];
  head: string;
  remote: { url: string | null; head: string | null; commits: Commit[] };
  installed: Record<string, string>;
  iamKeys: IamKey[];
  images: Record<string, ImageInfo>;
  registry: Record<string, ImageInfo>;
  container: { image: string; ok: boolean; log: string[] } | null;
  staging: Deployment | null;
  scans: Partial<Record<ToolName, ScanRecord>>;
  pipelineRuns: PipelineRun[];
  flags: Record<string, string | number | boolean>;
  activity: Activity[];
  hintsUsed: string[];
  startedAt: number;
  completedAt: number | null;
  achieved: string[];
}

export interface CmdResult {
  out: string[];
  code: number;
}
