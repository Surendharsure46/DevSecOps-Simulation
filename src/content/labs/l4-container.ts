import type { LabDef } from '../../engine/lab';
import { revOf } from '../../engine/shell';
import { baseFiles, CART_TESTS, SERVER_TEST, TEAM } from '../shopflow';
import { dockerignoreHas, finalStage, hasMinimalPinnedBase, headFiles, runsAsNonRoot } from './common';

const WEAK_DOCKERFILE = `FROM node:latest
ADD . /app
WORKDIR /app
ENV NODE_ENV=production
ENV DB_PASSWORD=ChangeMeTraining42
RUN apt-get update && apt-get install -y curl vim
RUN npm install
EXPOSE 3000
CMD npm start
`;

const freshImage = (s: Parameters<LabDef['objectives'][number]['check']>[0]) => {
  const tag = String(s.flags.lastBuiltImage ?? '');
  return s.flags.lastBuiltRev === revOf(s) ? s.images[tag] : undefined;
};

export const containerLab: LabDef = {
  id: 'container-hardening',
  level: 2,
  title: 'Harden the container image',
  track: 'Container security',
  minutes: 40,
  summary: 'Lint a Dockerfile, build and scan the image, then harden it: minimal pinned base, non-root user, no baked-in secrets, smaller attack surface — and keep it running.',
  story:
    'Platform engineering will only run images that pass the container baseline. The ShopFlow image runs as root on a 1 GB base with debugging tools and a password in its layers. Harden it — and make sure the container still starts.',
  ticket: 'SEC-352 — shopflow-api image fails the container baseline (root user, :latest, secrets in layers, fixable CRITICAL CVEs). Fix and provide a clean scan.',
  skills: ['Dockerfile best practice', 'Image scanning', 'Least privilege', 'Build-context hygiene'],
  tools: ['hadolint', 'docker build/run', 'trivy image', 'trivy config'],
  concepts: [
    { term: 'Minimal base', text: 'Slim, Alpine or distroless bases ship fewer packages, so fewer CVEs. Pin an explicit tag instead of :latest.' },
    { term: 'Non-root', text: 'Add USER so a compromised process does not own the container. Node images ship a "node" user; distroless has "nonroot".' },
    { term: 'Build context', text: 'COPY . copies everything not in .dockerignore — including .env and .git. Image layers are readable by anyone who can pull the image.' },
  ],
  openFile: 'Dockerfile',
  seed: () => ({
    history: [
      { message: 'Initial ShopFlow API', author: TEAM.priya, daysAgo: 90, files: baseFiles({ Dockerfile: WEAK_DOCKERFILE }) },
      { message: 'Add curl and vim for debugging in prod', author: TEAM.marco, daysAgo: 20, files: baseFiles({ Dockerfile: WEAK_DOCKERFILE }) },
    ],
    local: { '.env': 'DB_PASSWORD=LocalOnlyTraining77\nDB_HOST=localhost\n' },
  }),
  tests: [SERVER_TEST, ...CART_TESTS],
  objectives: [
    {
      id: 'lint',
      title: 'Lint the Dockerfile',
      guide: 'Run Hadolint and read each rule (DL3007, DL3020, …). Click a finding to jump to the line.',
      command: 'hadolint Dockerfile',
      hints: ['`trivy config .` gives a second, severity-ranked opinion.'],
      check: (s) => !!s.scans.hadolint,
    },
    {
      id: 'baseline',
      title: 'Build the current image and scan it (baseline)',
      guide: 'Build and scan before changing anything, so you can show the improvement afterwards.',
      command: 'docker build -t shopflow-api:1.4.0 . && trivy image shopflow-api:1.4.0',
      hints: ['Use the same tag each time; `docker images` lists what you built.'],
      check: (s) => !!s.scans['trivy-image'],
    },
    {
      id: 'base',
      title: 'Use a minimal, pinned base image',
      guide: 'Switch to e.g. `node:20-alpine`, `node:20-slim` or `gcr.io/distroless/nodejs20-debian12`. Remember: Alpine uses `apk`, distroless has no shell at all.',
      hints: ['FROM node:20-alpine', 'Do you still need curl and vim in production?'],
      check: (s) => hasMinimalPinnedBase(s.files.Dockerfile),
    },
    {
      id: 'user',
      title: 'Run as a non-root user',
      guide: 'Add a `USER` instruction near the end of the final stage. The user must exist in the base image.',
      hints: ['USER node (node images) or USER nonroot (distroless).'],
      check: (s) => runsAsNonRoot(s.files.Dockerfile),
    },
    {
      id: 'no-secrets',
      title: 'No secrets or repository metadata in the image',
      guide: 'Remove the password ENV (inject it at runtime), use COPY instead of ADD, and add a `.dockerignore` excluding `.env`, `.git` and `node_modules`. Rebuild to prove it.',
      hints: ['printf ".env\\n.git\\nnode_modules\\n" > .dockerignore', 'Rebuild after editing — checks use your latest build.'],
      check: (s) => {
        const img = freshImage(s);
        const st = finalStage(s.files.Dockerfile);
        return !!img && !img.hasEnvFile && !img.hasGitDir && !!st && st.secretEnv.length === 0 && dockerignoreHas(s.files, '.env', '.git');
      },
    },
    {
      id: 'clean-scan',
      title: 'Fresh image scan: no fixable HIGH/CRITICAL, no secrets',
      guide: 'Rebuild and scan the hardened image. Unfixed OS CVEs may remain on some bases — that is a documented, accepted risk; fixable ones are not.',
      command: 'docker build -t shopflow-api:1.4.0 . && trivy image --severity HIGH,CRITICAL shopflow-api:1.4.0',
      hints: ['trivy image --ignore-unfixed shows only what you can act on.'],
      check: (s) => {
        const img = freshImage(s);
        const scan = s.scans['trivy-image'];
        return !!img && !!scan && scan.target === img.tag && scan.rev === revOf(s) && !scan.findings.some((f) => (f.severity === 'CRITICAL' || f.severity === 'HIGH') && f.fixed !== '(no fix yet)');
      },
    },
    {
      id: 'runs',
      title: 'The hardened container starts',
      guide: 'Security that breaks the service is not done. Run the latest image and confirm it listens on port 3000.',
      command: 'docker run --rm -p 3000:3000 shopflow-api:1.4.0',
      hints: ['Distroless: use exec-form CMD ["src/server.js"] — node is already the entrypoint.', 'Shell-form CMD needs /bin/sh.'],
      check: (s) => {
        const img = freshImage(s);
        return !!img && !!s.container?.ok && s.container.image === img.tag;
      },
    },
    {
      id: 'commit',
      title: 'Commit the Dockerfile and .dockerignore',
      guide: 'Commit both files so CI builds the hardened image.',
      command: 'git add Dockerfile .dockerignore && git commit -m "Harden container image"',
      hints: ['git status should show nothing left to commit for these files.'],
      check: (s) => {
        const h = headFiles(s);
        return h.Dockerfile === s.files.Dockerfile && runsAsNonRoot(h.Dockerfile) && hasMinimalPinnedBase(h.Dockerfile) && dockerignoreHas(h, '.env', '.git');
      },
    },
    {
      id: 'polish',
      title: 'Image under 250 MB with a HEALTHCHECK',
      guide: 'Production polish: install only production deps (`npm ci --omit=dev`), consider a multi-stage build, add a HEALTHCHECK.',
      hints: ['HEALTHCHECK CMD wget -qO- http://localhost:3000/health || exit 1 (not available on distroless).'],
      bonus: true,
      check: (s) => {
        const img = freshImage(s);
        return !!img && img.sizeMb < 250 && img.healthcheck;
      },
    },
  ],
};
