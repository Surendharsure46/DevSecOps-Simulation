import type { LabDef } from '../../engine/lab';
import { failingTests, testsGreenNow } from '../../engine/lab';
import { baseFiles, CART_JS_OK, CART_TESTS, ORDER_TESTS, TEAM } from '../shopflow';
import { headFiles, isPushed, runForHead } from './common';

export const CI_BASIC = `name: ci
on:
  push:
    branches: [main]

jobs:
  test:
    name: Build & test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - name: Install dependencies
        run: npm ci
      - name: Unit tests
        run: npm test
`;

const BROKEN_CART = CART_JS_OK.replace('sum + item.price * item.quantity', 'sum + item.price');

export const redBuild: LabDef = {
  id: 'red-build',
  level: 0,
  title: 'Fix a red build',
  track: 'Foundations · CI/CD',
  minutes: 15,
  summary: 'Read a failing pipeline, reproduce it locally, fix the code and ship a green build through Git.',
  story:
    "First day on the ShopFlow platform team. The main branch pipeline is red after yesterday's merge and nobody can deploy. Work out why, fix it properly (no disabling tests), and get main green again.",
  ticket: 'INC-1042 — main is red. Restore a green pipeline. Tests must not be skipped or weakened.',
  skills: ['Reading CI logs', 'Git basics', 'Tests as a quality gate'],
  tools: ['GitHub Actions', 'git', 'npm', 'Jest'],
  concepts: [
    { term: 'Pipeline', text: 'Each push runs .github/workflows/ci.yml on a fresh runner. A failed step stops everything after it.' },
    { term: 'Reproduce first', text: 'Run the exact command CI ran (npm test) locally before you change anything.' },
    { term: 'Only commits count', text: 'CI sees what you commit and push — not what is open in your editor.' },
  ],
  openFile: 'src/lib/cart.js',
  seed: () => ({
    history: [
      { message: 'Initial ShopFlow API', author: TEAM.priya, daysAgo: 30, files: baseFiles({ '.github/workflows/ci.yml': CI_BASIC }) },
      { message: 'Simplify cart total calculation', author: TEAM.marco, daysAgo: 1, files: baseFiles({ '.github/workflows/ci.yml': CI_BASIC, 'src/lib/cart.js': BROKEN_CART }) },
    ],
    runInitialPipeline: true,
  }),
  tests: [...CART_TESTS, ...ORDER_TESTS],
  objectives: [
    {
      id: 'read-log',
      title: 'Open the failed pipeline run and read the failing step log',
      guide: 'Go to the **Pipeline** tab. Run #1 is red — click it, then click the step marked ✕ to read its log.',
      hints: ['Bottom panel → Pipeline → run #1 → "Unit tests".'],
      check: (s) => s.flags.viewedFailedLog === true,
    },
    {
      id: 'repro',
      title: 'Reproduce the failure locally',
      guide: 'The failing step ran `npm test`. Run the same command in the **Terminal**.',
      command: 'npm test',
      hints: ['Type the command and press Enter.'],
      check: (s) => s.flags.testsFailedOnce === true,
    },
    {
      id: 'history',
      title: 'Identify the commit that introduced the bug',
      guide: '`git log --oneline` lists commits; `git show HEAD` shows what the latest one changed.',
      command: 'git show HEAD',
      hints: ['Look at the red (-) and green (+) lines in src/lib/cart.js.'],
      bonus: true,
      check: (s) => s.flags.inspectedHistory === true,
    },
    {
      id: 'fix',
      title: 'Fix the bug so every unit test passes locally',
      guide: 'In `src/lib/cart.js` each line must count **price × quantity**. Edit, then run `npm test` again.',
      command: 'npm test',
      hints: ['Expected 25 for 2×10 + 1×5.', 'Multiply item.price by item.quantity inside reduce().'],
      check: (s) => testsGreenNow(redBuild, s),
    },
    {
      id: 'commit',
      title: 'Commit the fix',
      guide: 'Stage and commit: `git add src/lib/cart.js` then `git commit -m "..."` — or use **Commit & Push**.',
      command: 'git commit -am "Fix cart total to include quantity"',
      hints: ['git status shows modified files that are not committed yet.'],
      check: (s) => failingTests(redBuild, headFiles(s), s.installed).length === 0,
    },
    {
      id: 'green',
      title: 'Push and get a green pipeline',
      guide: '`git push` publishes the commit and triggers CI. Check the Pipeline tab.',
      command: 'git push',
      hints: ['"Everything up-to-date" means nothing new was committed.'],
      check: (s) => runForHead(s)?.status === 'passed' && isPushed(s),
    },
  ],
};
