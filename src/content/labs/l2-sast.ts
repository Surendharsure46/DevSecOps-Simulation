import type { LabDef } from '../../engine/lab';
import { scanFresh, testsGreenNow } from '../../engine/lab';
import { runSast } from '../../engine/sast';
import { baseFiles, CART_TESTS, ORDER_TESTS, ORDERS_VULN, ordersSecure, PRODUCTS_JS, PRODUCTS_TEST, SERVER_TEST, TEAM } from '../shopflow';
import { headFiles } from './common';

export const sastLab: LabDef = {
  id: 'sast-orders',
  level: 1,
  title: 'Injection flaws in the Orders API',
  track: 'SAST · Secure coding',
  minutes: 35,
  summary: 'Scan with Semgrep, fix SQL injection and eval() with parameterised, validated code, and triage a false positive with a justified suppression.',
  story:
    'An external code review says the Orders API builds SQL from request input. Run static analysis, fix every true positive without breaking the API contract, and deal with any false positives the way a reviewer would accept.',
  ticket: 'SEC-327 — Injection risks in src/routes/orders.js. All true positives fixed, scanner clean, no real issue suppressed, tests green.',
  skills: ['Static analysis', 'Parameterised queries', 'Input validation', 'Finding triage'],
  tools: ['semgrep', 'npm test'],
  concepts: [
    { term: 'Parameterised query', text: "Pass values separately: db.query('... WHERE id = $1', [id]). The database never treats them as SQL." },
    { term: 'eval()', text: 'Evaluating request data runs attacker-chosen code. Parse input into a strict type and validate it instead.' },
    { term: 'False positive', text: 'A finding where the flagged value cannot be influenced by users. Document why and suppress narrowly (nosemgrep: rule-id) — never blanket-ignore.' },
  ],
  openFile: 'src/routes/orders.js',
  seed: () => ({
    history: [
      { message: 'Initial ShopFlow API', author: TEAM.priya, daysAgo: 60, files: baseFiles() },
      { message: 'Orders: customer filter, receipts and flexible discounts', author: TEAM.marco, daysAgo: 5, files: baseFiles({ 'src/routes/orders.js': ORDERS_VULN, 'src/routes/products.js': PRODUCTS_JS }) },
    ],
  }),
  tests: [...ORDER_TESTS, PRODUCTS_TEST, SERVER_TEST, ...CART_TESTS],
  objectives: [
    {
      id: 'scan',
      title: 'Run a Semgrep scan of the repository',
      guide: 'Run Semgrep with the default ruleset and read each finding: rule id, file, line and explanation.',
      command: 'semgrep scan --config auto',
      hints: ['Findings also appear in the Findings tab — click one to jump to the line.'],
      check: (s) => s.flags.semgrepRev !== undefined,
    },
    {
      id: 'list-query',
      title: 'GET /orders uses a parameterised query',
      guide: 'Replace the string-built SQL with a placeholder (`$1`) and pass `[req.query.customer]` as the second argument to `db.query`.',
      hints: ["db.query('SELECT id, total, status FROM orders WHERE customer_id = $1', [req.query.customer])"],
      check: (s) => ordersSecure(s.files).list,
    },
    {
      id: 'receipt-query',
      title: 'GET /orders/:id/receipt uses a parameterised query',
      guide: 'Same fix for the template-literal query: placeholder plus a values array.',
      hints: ["db.query('SELECT order_id, total FROM receipts WHERE order_id = $1', [req.params.id])"],
      check: (s) => ordersSecure(s.files).receipt,
    },
    {
      id: 'no-eval',
      title: 'Discount endpoint no longer evaluates request input',
      guide: 'Accept a numeric `percent`, validate it is between 0 and 100 (else 400) and compute the total in code. The route must still return `{ total }`.',
      hints: ['const percent = Number(req.body.percent); if (!Number.isFinite(percent) || percent < 0 || percent > 100) return res.status(400).json({...});'],
      check: (s) => ordersSecure(s.files).discount,
    },
    {
      id: 'triage',
      title: 'Triage the products.js finding correctly',
      guide:
        'The featured-products query concatenates a constant, not user input. Either rewrite it with a placeholder, or add `// nosemgrep: <rule-id> -- <reason>` on the line above with a real justification. Suppressing anything in orders.js is not acceptable.',
      hints: ['A justification explains why the value is not attacker-controlled.', 'Parameterising it anyway is also a valid, simpler answer.'],
      check: (s) => {
        const { matches } = runSast({ 'src/routes/products.js': s.files['src/routes/products.js'] ?? '' });
        const active = matches.filter((m) => !m.suppressed);
        const sup = matches.filter((m) => m.suppressed);
        const justified = sup.every((m) => {
          const lines = (s.files['src/routes/products.js'] ?? '').split('\n');
          const txt = (lines[m.line - 1] + ' ' + (lines[m.line - 2] ?? '')).replace(/.*nosemgrep(:\s*[\w.-]+)?/, '');
          return txt.replace(/[^a-zA-Z ]/g, ' ').trim().split(/\s+/).length >= 3;
        });
        return active.length === 0 && justified && PRODUCTS_TEST.run(s.files, s.installed) === null && !/nosemgrep/.test(s.files['src/routes/orders.js'] ?? '');
      },
    },
    {
      id: 'verify',
      title: 'Re-scan clean and tests green on the current code',
      guide: 'Run Semgrep and `npm test` again after your last edit. Both must pass on the same version of the code.',
      command: 'semgrep scan --config auto && npm test',
      hints: ['Any edit after a scan makes the scan stale — re-run both.'],
      check: (s) => scanFresh(s, 'semgrep') && (s.scans.semgrep?.findings.length ?? 1) === 0 && testsGreenNow(sastLab, s),
    },
    {
      id: 'commit',
      title: 'Commit the fixes',
      guide: 'Commit your changes so they can be reviewed and shipped.',
      command: 'git commit -am "Fix injection flaws in orders API"',
      hints: ['git status, git add, git commit.'],
      check: (s) => {
        const o = ordersSecure(headFiles(s));
        return o.list && o.receipt && o.discount;
      },
    },
  ],
};
