import type { LabDef } from '../../engine/lab';
import type { Files } from '../../engine/types';
import { helmetEnabled, sessionCookie } from '../../engine/appmodel';
import { kyverno, parseWorkloads, STAGING_HOST } from '../../engine/staging';
import { readLock } from '../../engine/sca';
import { baseFiles, CART_TESTS, npmFiles, ORDER_TESTS, ORDERS_VULN, ordersSecure, PRODUCTS_TEST, SERVER_JS, SERVER_TEST, TEAM } from '../shopflow';
import { dockerignoreHas, hasMinimalPinnedBase, headFiles, isPushed, runForHead, runsAsNonRoot } from './common';
import { bypasses } from './l6-pipeline-gate';

const SERVER_WITH_SESSION = SERVER_JS.replace(
  "const express = require('express');",
  "const express = require('express');\nconst session = require('express-session');",
).replace(
  'app.use(express.json());',
  `app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { httpOnly: false, maxAge: 3600000 },
}));`,
);

const DOCKERFILE = `FROM node:20
WORKDIR /app
COPY . .
RUN npm ci
EXPOSE 3000
CMD ["node", "src/server.js"]
`;

const DEPLOYMENT = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: shopflow-api
  namespace: shop
spec:
  replicas: 2
  selector:
    matchLabels:
      app: shopflow-api
  template:
    metadata:
      labels:
        app: shopflow-api
    spec:
      containers:
        - name: api
          image: registry.shopflow.local/shopflow-api:1.3.9
          ports:
            - containerPort: 3000
          securityContext:
            privileged: true
`;

const CI = `name: ci
on:
  push:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: npm test

  security:
    needs: test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Secrets
        run: gitleaks git -v --redact
      - name: SAST
        run: semgrep scan --config auto || true
      - name: Dependencies
        run: trivy fs --severity HIGH,CRITICAL --exit-code 1 .
      - name: Dockerfile lint
        run: hadolint --failure-threshold error Dockerfile

  build:
    needs: security
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker build -t registry.shopflow.local/shopflow-api:\${{ github.sha }} .
      - name: Image scan
        run: trivy image --severity CRITICAL --exit-code 0 registry.shopflow.local/shopflow-api:\${{ github.sha }}
      - run: docker push registry.shopflow.local/shopflow-api:\${{ github.sha }}

  deploy:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: kubectl apply -f k8s/
      - run: kubectl set image deployment/shopflow-api api=registry.shopflow.local/shopflow-api:\${{ github.sha }}

  dast:
    needs: deploy
    runs-on: ubuntu-latest
    steps:
      - name: ZAP full scan
        uses: zaproxy/action-full-scan@v0.12.0
        with:
          target: https://${STAGING_HOST}
`;

function gateProblems(wf: string): string[] {
  const p = bypasses(wf);
  if (!/trivy\s+image[^\n]*--exit-code[ =]1/.test(wf)) p.push('image scan does not fail on findings');
  const zapViaAction = /zaproxy\/action-(full-scan|baseline)/.test(wf);
  if (zapViaAction && !/fail_action:\s*['"]?true/.test(wf)) p.push('ZAP action has fail_action false');
  if (!zapViaAction && !/zap-(full-scan|baseline)\.py/.test(wf)) p.push('no DAST stage');
  if (/zap-(full-scan|baseline)\.py[^\n]*\s-I\b/.test(wf)) p.push('ZAP -I ignores warnings');
  return p;
}

function manifestPasses(files: Files): boolean {
  const src = files['k8s/deployment.yaml'];
  if (!src) return false;
  const { workloads, error } = parseWorkloads(src);
  return !error && workloads.length > 0 && workloads.every((w) => kyverno(w).length === 0);
}

export const capstoneLab: LabDef = {
  id: 'capstone',
  level: 4,
  title: 'Capstone: ship ShopFlow securely',
  track: 'End-to-end DevSecOps',
  minutes: 90,
  summary: 'Own the whole path: run DAST on staging, close the pipeline bypasses, fix code, headers, image and Kubernetes manifest, and ship a green, gated, scanned release.',
  story:
    'You are the DevSecOps engineer for the 1.4.0 release. The pipeline exists but has gaps, the deploy is being rejected by the cluster admission policy, and staging still runs an old, vulnerable build. Release only when every gate is real and the deployed app scans clean.',
  ticket: 'REL-140 — Release shopflow-api 1.4.0. Requirements: no gate bypasses, image scan blocking, DAST blocking, admission policies satisfied, deployed build passes a full ZAP scan.',
  skills: ['DAST', 'Pipeline hardening', 'Secure headers & cookies', 'Kubernetes admission', 'Release ownership'],
  tools: ['zap-full-scan.py', 'curl', 'semgrep', 'trivy', 'hadolint', 'docker', 'kubectl', 'kyverno'],
  concepts: [
    { term: 'DAST', text: 'Dynamic testing attacks the running app over HTTP — it finds missing headers, insecure cookies and injectable endpoints that code review may miss.' },
    { term: 'Admission control', text: 'Kyverno rejects workloads that run privileged, as root, with :latest tags or without resource limits — before they ever start.' },
    { term: 'Defence in depth', text: 'Each layer (code, deps, image, manifest, runtime scan) catches different failures. A release is only as strong as its weakest gate.' },
  ],
  openFile: '.github/workflows/ci.yml',
  seed: () => {
    const files = baseFiles({
      ...npmFiles({ express: '^4.21.2', 'express-session': '^1.18.1', pg: '^8.13.1' }, { express: '4.21.2', 'express-session': '1.18.1', pg: '8.13.1', jest: '29.7.0' }),
      'src/server.js': SERVER_WITH_SESSION,
      'src/routes/orders.js': ORDERS_VULN,
      Dockerfile: DOCKERFILE,
      'k8s/deployment.yaml': DEPLOYMENT,
      '.github/workflows/ci.yml': CI,
    });
    return {
      history: [
        { message: 'ShopFlow API 1.3.9', author: TEAM.priya, daysAgo: 21, files },
        { message: 'Add release pipeline', author: TEAM.dana, daysAgo: 2, files },
      ],
      local: { '.env': 'SESSION_SECRET=LocalOnlyTrainingSession\nDB_PASSWORD=LocalOnlyTraining77\n' },
      registryFromHead: 'registry.shopflow.local/shopflow-api:1.3.9',
      stagingFromHead: true,
      runInitialPipeline: true,
    };
  },
  tests: [...ORDER_TESTS, PRODUCTS_TEST, SERVER_TEST, ...CART_TESTS],
  objectives: [
    {
      id: 'dast-baseline',
      title: 'Run a full ZAP scan against staging and review the alerts',
      guide: `Scan the running staging app. Note every alert ID — they become your fix list. Inspect headers with \`curl -i https://${STAGING_HOST}/health\`.`,
      command: `zap-full-scan.py -t https://${STAGING_HOST}`,
      hints: ['High alerts come from the active scan; header and cookie alerts from passive rules.'],
      check: (s) => s.flags.zapFullAt !== undefined,
    },
    {
      id: 'gates',
      title: 'Every gate in the committed pipeline actually blocks',
      guide: 'Remove `|| true`, make SAST fail on findings, make the image scan exit 1, and make DAST fail the build (`fail_action: true`).',
      hints: ['Read the zaproxy action docs: fail_action defaults to false.', 'trivy image --severity HIGH,CRITICAL --exit-code 1 --ignore-unfixed …'],
      check: (s) => gateProblems(headFiles(s)['.github/workflows/ci.yml'] ?? '').length === 0,
    },
    {
      id: 'code',
      title: 'Orders API: no injection, no eval (committed)',
      guide: 'Apply what you learned in the SAST lab to `src/routes/orders.js`.',
      hints: ['Parameterised queries and a validated numeric discount.'],
      check: (s) => {
        const o = ordersSecure(headFiles(s));
        return o.list && o.receipt && o.discount;
      },
    },
    {
      id: 'headers',
      title: 'Security headers and a hardened session cookie (committed)',
      guide: 'Install and enable `helmet`, and set the session cookie to `httpOnly: true`, `secure: true`, `sameSite: "lax"`.',
      command: 'npm install helmet@8.0.0',
      hints: ["const helmet = require('helmet'); app.use(helmet());"],
      check: (s) => {
        const h = headFiles(s);
        const inst = readLock(h) ?? {};
        const c = sessionCookie(h, inst);
        return helmetEnabled(h, inst) && c.present && c.httpOnly && c.secure && !!c.sameSite;
      },
    },
    {
      id: 'image',
      title: 'Container: minimal pinned base, non-root, clean build context (committed)',
      guide: 'Apply the container baseline: minimal base, `USER`, `.dockerignore` with `.env` and `.git`.',
      hints: ['FROM node:20-alpine … USER node'],
      check: (s) => {
        const h = headFiles(s);
        return runsAsNonRoot(h.Dockerfile) && hasMinimalPinnedBase(h.Dockerfile) && dockerignoreHas(h, '.env', '.git');
      },
    },
    {
      id: 'manifest',
      title: 'Kubernetes manifest passes admission policies (committed)',
      guide: 'Check it locally with `kyverno apply` first, then fix the securityContext, resources and image tag.',
      command: 'kyverno apply policies/ --resource k8s/deployment.yaml',
      hints: ['securityContext: { runAsNonRoot: true, allowPrivilegeEscalation: false }', 'resources: requests cpu + limits memory'],
      check: (s) => manifestPasses(headFiles(s)),
    },
    {
      id: 'release',
      title: 'Green pipeline deployed your commit to staging, DAST passed',
      guide: 'Push and follow the run through test → security → build → deploy → dast.',
      hints: ['Read the failing step log — each one tells you exactly which gate tripped.'],
      check: (s) => {
        const r = runForHead(s);
        return !!r && r.status === 'passed' && isPushed(s) && r.jobs.some((j) => j.id === 'dast' && j.status === 'passed') && s.staging?.commit === s.head;
      },
    },
    {
      id: 'evidence',
      title: 'Evidence: a full ZAP scan of the new deployment with zero alerts',
      guide: 'Re-scan staging after the release so the report reflects what is actually deployed.',
      command: `zap-full-scan.py -t https://${STAGING_HOST} -r zap-report.html`,
      hints: ['The scan must run after the latest deploy.'],
      check: (s) => !!s.staging && s.staging.commit === s.head && s.flags.zapFullAt === s.staging.at && (s.scans.zap?.findings.length ?? 1) === 0,
    },
  ],
};
