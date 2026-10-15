import type { LabDef } from '../../engine/lab';
import { failingTests, scanFresh } from '../../engine/lab';
import { ignoredBy } from '../../engine/git';
import { scanFiles } from '../../engine/secrets';
import { baseFiles, CART_TESTS, TEAM } from '../shopflow';
import { headFiles, isPushed } from './common';

// Training values only — visibly fake, never valid credentials.
export const FAKE_KEY_ID = 'AKIAFAKETRAININGKEY2';
export const FAKE_SECRET = 'TrainingOnlyFakeSecret/NotReal/Q7x9';

const CONFIG_WITH_KEY = `// S3 settings for invoice PDF uploads
module.exports = {
  region: 'eu-west-1',
  bucket: 'shopflow-invoices',
  accessKeyId: '${FAKE_KEY_ID}',
  secretAccessKey: '${FAKE_SECRET}',
};
`;

const UPLOADER = `const config = require('../config/storage');

async function uploadInvoice(orderId, pdf) {
  const objectName = \`invoices/\${orderId}.pdf\`;
  return { bucket: config.bucket, objectName, size: pdf.length };
}

module.exports = { uploadInvoice };
`;

export const secretsLab: LabDef = {
  id: 'secrets-history',
  level: 1,
  title: 'Credential committed to Git',
  track: 'Secrets management',
  minutes: 30,
  summary: 'Find a committed cloud credential with Gitleaks, disable it, move config to environment variables, rewrite history and prove the repo is clean.',
  story:
    "Secret scanning flagged a cloud access key in shopflow-api. Run it as a proper incident: confirm the finding, disable the credential, fix the code, clean the repository history and record evidence that it is gone. (All credentials in this lab are fake training values.)",
  ticket: 'SEC-311 — Cloud credential exposed in shopflow-api. Contain, remove from code and history, prevent recurrence, provide a clean scan as evidence.',
  skills: ['Secret scanning', 'Credential revocation', 'Environment-based config', 'Git history rewrite'],
  tools: ['gitleaks', 'aws iam', 'git filter-repo'],
  concepts: [
    { term: 'Disable first', text: 'A pushed secret must be treated as exposed. Deactivate it before tidying code.' },
    { term: 'History', text: 'Deleting a line in a new commit leaves the secret in older commits. Scanners check all of them.' },
    { term: 'Config from environment', text: 'Code reads credentials from environment variables or a secrets manager; the repo holds none.' },
  ],
  openFile: 'src/config/storage.js',
  seed: () => {
    const base = baseFiles({ '.gitignore': 'node_modules/\ncoverage/\n*.log\n' });
    const withKey = { ...base, 'src/config/storage.js': CONFIG_WITH_KEY, 'src/services/invoices.js': UPLOADER };
    return {
      history: [
        { message: 'Initial ShopFlow API', author: TEAM.priya, daysAgo: 40, files: base },
        { message: 'Add invoice upload to object storage', author: TEAM.marco, daysAgo: 12, files: withKey },
        { message: 'Update README', author: TEAM.dana, daysAgo: 3, files: { ...withKey, 'README.md': base['README.md'] + '\nInvoices are stored in object storage.\n' } },
      ],
      iamKeys: [{ id: FAKE_KEY_ID, user: 'svc-invoices', status: 'Active', created: '2026-09-02T08:14:00Z' }],
      flags: { leakedKeyId: FAKE_KEY_ID },
    };
  },
  tests: [
    ...CART_TESTS,
    {
      suite: 'tests/invoices.test.js',
      name: 'storage config defines region, bucket and credentials',
      run: (fs) => {
        const src = fs['src/config/storage.js'];
        if (!src) return "Cannot find module '../config/storage'";
        for (const k of ['region', 'bucket', 'accessKeyId', 'secretAccessKey']) if (!new RegExp(`\\b${k}\\s*:`).test(src)) return `Expected config to define "${k}"`;
        return null;
      },
    },
  ],
  objectives: [
    {
      id: 'detect',
      title: 'Scan the whole Git history for secrets',
      guide: 'Run Gitleaks against history. Note the rule, file, commit and author of each finding.',
      command: 'gitleaks git -v',
      hints: ['`gitleaks detect -v` is the older spelling of the same scan.'],
      check: (s) => s.flags.gitleaksGitRev !== undefined,
    },
    {
      id: 'audit',
      title: 'Check the audit trail for use of the key',
      guide: 'Decide whether this is a near-miss or a breach: look up audit events for the key id.',
      command: `aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=${FAKE_KEY_ID}`,
      hints: ['Compare SourceIPAddress with your own application servers (10.20.x.x).'],
      bonus: true,
      check: (s) => s.flags.investigatedKey === true,
    },
    {
      id: 'disable',
      title: 'Deactivate the exposed access key',
      guide: 'List the service user\'s keys, then set the exposed one to Inactive (or delete it).',
      command: `aws iam update-access-key --user-name svc-invoices --access-key-id ${FAKE_KEY_ID} --status Inactive`,
      hints: ['aws iam list-access-keys --user-name svc-invoices'],
      check: (s) => !s.iamKeys.some((k) => k.id === FAKE_KEY_ID && k.status === 'Active'),
    },
    {
      id: 'env-config',
      title: 'Read credentials from environment variables',
      guide: 'In `src/config/storage.js` use `process.env.AWS_ACCESS_KEY_ID` and `process.env.AWS_SECRET_ACCESS_KEY`. No tracked file may contain a secret.',
      hints: ['accessKeyId: process.env.AWS_ACCESS_KEY_ID,', '`gitleaks dir .` scans the working tree only.'],
      check: (s) => {
        const src = s.files['src/config/storage.js'] ?? '';
        const ign = ignoredBy(s.files);
        const tracked = Object.fromEntries(Object.entries(s.files).filter(([p]) => !ign(p)));
        return /process\.env\.AWS_ACCESS_KEY_ID/.test(src) && /process\.env\.AWS_SECRET_ACCESS_KEY/.test(src) && scanFiles(tracked).length === 0 && failingTests(secretsLab, s.files, s.installed).length === 0;
      },
    },
    {
      id: 'ignore-env',
      title: 'Make Git ignore local .env files',
      guide: 'Add `.env` to `.gitignore` so local secrets can never be staged.',
      command: 'echo ".env" >> .gitignore',
      hints: ['Create a .env and run git status — it must not be listed.'],
      check: (s) => ignoredBy(s.files)('.env'),
    },
    {
      id: 'rewrite',
      title: 'Remove the secret from history and update the remote',
      guide:
        'Commit your fix. Write a replacements file with one `old==>REMOVED` line for the key id and one for the secret, run `git filter-repo --replace-text <file> --force`, add the remote back (filter-repo removes it deliberately) and force-push. Then delete the replacements file.',
      hints: [
        'git add -A && git commit -m "Read storage credentials from env"',
        'git remote add origin https://git.shopflow.local/shopflow/shopflow-api.git',
        'git push --force origin main',
      ],
      check: (s) =>
        isPushed(s) &&
        s.remote.commits.every((c) => Object.values(c.files).every((t) => !t.includes(FAKE_KEY_ID) && !t.includes(FAKE_SECRET))) &&
        /process\.env\.AWS_SECRET_ACCESS_KEY/.test(headFiles(s)['src/config/storage.js'] ?? ''),
    },
    {
      id: 'evidence',
      title: 'Evidence: a clean Gitleaks history scan after the rewrite',
      guide: 'Scan history again. A clean result is the evidence you attach to the ticket.',
      command: 'gitleaks git -v',
      hints: ['Make sure the replacements file was not committed.'],
      check: (s) => scanFresh(s, 'gitleaks') && s.scans.gitleaks?.target === 'git history' && s.scans.gitleaks.findings.length === 0 && isPushed(s),
    },
  ],
};
