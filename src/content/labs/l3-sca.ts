import type { LabDef } from '../../engine/lab';
import { testsGreenNow } from '../../engine/lab';
import { auditInstalled, lockInSync, readLock, readPkg } from '../../engine/sca';
import { cmpVer } from '../../engine/util';
import { baseFiles, CART_TESTS, npmFiles, SERVER_TEST, TEAM } from '../shopflow';
import { headFiles, isPushed, requiredModulesInstalled } from './common';

const DEPS = { express: '^4.17.1', lodash: '4.17.15', jsonwebtoken: '^8.5.1', axios: '^0.21.0', minimist: '^1.2.5', pg: '^8.13.1' };
const LOCK = { express: '4.17.1', lodash: '4.17.15', jsonwebtoken: '8.5.1', axios: '0.21.0', minimist: '1.2.5', pg: '8.13.1', jest: '29.7.0' };

const extra = {
  'src/auth.js': `const jwt = require('jsonwebtoken');

function verifyToken(token) {
  return jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
}

module.exports = { verifyToken };
`,
  'src/lib/format.js': `const _ = require('lodash');

module.exports = { titleCase: (s) => _.startCase(_.toLower(s)) };
`,
  'src/services/shipping.js': `const axios = require('axios');

async function quote(postcode) {
  const { data } = await axios.get('https://rates.shipping.local/quote', { params: { postcode } });
  return data;
}

module.exports = { quote };
`,
  'src/cli.js': `const args = require('minimist')(process.argv.slice(2));

if (args.reindex) console.log('reindexing search…');
`,
};

function noHighOrCritical(installed: Record<string, string>) {
  return !auditInstalled(installed).some((h) => h.adv.severity === 'HIGH' || h.adv.severity === 'CRITICAL');
}

export const scaLab: LabDef = {
  id: 'sca-deps',
  level: 2,
  title: 'Vulnerable dependencies',
  track: 'SCA · Supply chain',
  minutes: 30,
  summary: 'Audit npm dependencies with Trivy and npm audit, upgrade safely (watch for breaking majors), keep the lockfile in sync and publish a CycloneDX SBOM.',
  story:
    "Release 1.4.0 is blocked: the security team's weekly report shows a CRITICAL and several HIGH vulnerabilities in shopflow-api's dependencies. Upgrade what is needed without breaking the service, and hand over an SBOM for the release record.",
  ticket: 'SEC-340 — No HIGH/CRITICAL dependency vulnerabilities allowed for release 1.4.0. Lockfile committed, service still boots, SBOM attached.',
  skills: ['Dependency auditing', 'Semantic versioning', 'Lockfiles', 'SBOM generation'],
  tools: ['trivy fs', 'npm audit', 'npm install', 'syft'],
  concepts: [
    { term: 'Lockfile', text: 'package-lock.json pins exact versions. CI installs from it with npm ci — so upgrades only count once the lockfile is updated and committed.' },
    { term: 'Breaking majors', text: 'Jumping a major version (4.x → 5.x) can break the app. Prefer the smallest version that contains the fix, then run the tests.' },
    { term: 'SBOM', text: 'A Software Bill of Materials lists every component and version you ship, so future CVEs can be matched quickly.' },
  ],
  openFile: 'package.json',
  seed: () => ({
    history: [
      { message: 'Initial ShopFlow API', author: TEAM.priya, daysAgo: 400, files: baseFiles({ ...npmFiles(DEPS, LOCK), ...extra }) },
      { message: 'Add shipping quotes and admin CLI', author: TEAM.dana, daysAgo: 200, files: baseFiles({ ...npmFiles(DEPS, LOCK), ...extra }) },
    ],
  }),
  tests: [SERVER_TEST, requiredModulesInstalled, ...CART_TESTS],
  objectives: [
    {
      id: 'audit',
      title: 'Scan dependencies for known vulnerabilities',
      guide: 'Run Trivy on the repository (it reads package-lock.json). Compare with `npm audit`.',
      command: 'trivy fs .',
      hints: ['trivy fs --severity HIGH,CRITICAL . narrows the table.'],
      check: (s) => s.flags.trivyFsRev !== undefined || !!s.scans['npm-audit'],
    },
    {
      id: 'critical',
      title: 'Fix the CRITICAL vulnerability',
      guide: 'Find the package with the CRITICAL advisory and install the first fixed version. It is still used by `src/cli.js`, so do not remove it.',
      command: 'npm install minimist@1.2.8',
      hints: ['Look at the "Fixed Version" column.'],
      check: (s) => !!s.installed.minimist && cmpVer(s.installed.minimist, '1.2.6') >= 0,
    },
    {
      id: 'high',
      title: 'No HIGH or CRITICAL vulnerabilities remain',
      guide: 'Upgrade the remaining packages. `npm audit fix` handles same-major fixes; one fix needs a new major version — install it explicitly and re-run the tests.',
      command: 'npm audit fix',
      hints: ['npm audit fix --force upgrades majors too — check what it will install first.', 'Avoid express 5.x here: the server uses a wildcard route that 5.x rejects.'],
      check: (s) => noHighOrCritical(s.installed),
    },
    {
      id: 'healthy',
      title: 'Lockfile in sync and service still boots (tests green)',
      guide: 'Run `npm test`. If the server fails to boot after an upgrade, read the error and choose a compatible version.',
      command: 'npm test',
      hints: ['TypeError: Missing parameter name → you installed express 5.'],
      check: (s) => {
        const { pkg } = readPkg(s.files);
        return !!pkg && lockInSync(pkg, readLock(s.files)).length === 0 && testsGreenNow(scaLab, s);
      },
    },
    {
      id: 'sbom',
      title: 'Generate a CycloneDX SBOM that matches the lockfile',
      guide: 'Produce `sbom.cdx.json` with Syft (or Trivy). It must list the versions you are actually shipping now.',
      command: 'syft . -o cyclonedx-json=sbom.cdx.json',
      hints: ['Regenerate it after your final upgrade.'],
      check: (s) => {
        const lock = readLock(s.files) ?? {};
        return Object.entries(s.files).some(([p, t]) => {
          if (!p.endsWith('.json') || p === 'package.json' || p === 'package-lock.json') return false;
          try {
            const j = JSON.parse(t) as { bomFormat?: string; components?: { name: string; version: string }[] };
            if (j.bomFormat !== 'CycloneDX' || !j.components) return false;
            return Object.entries(lock).every(([n, v]) => j.components!.some((c) => c.name === n && c.version === v));
          } catch {
            return false;
          }
        });
      },
    },
    {
      id: 'ship',
      title: 'Commit package.json and the lockfile, then push',
      guide: 'CI installs from the committed lockfile, so commit both files (and the SBOM) and push.',
      command: 'git add package.json package-lock.json sbom.cdx.json && git commit -m "Upgrade vulnerable dependencies" && git push',
      hints: ['git diff --staged shows exactly what you are committing.'],
      check: (s) => isPushed(s) && noHighOrCritical(readLock(headFiles(s)) ?? { minimist: '1.2.5' }),
    },
    {
      id: 'zero',
      title: 'Zero known vulnerabilities of any severity',
      guide: 'Go further: clear the MEDIUM and LOW advisories too, without changing major versions you do not need to.',
      hints: ['axios 1.x and express ≥ 4.20 close the remaining ones.'],
      bonus: true,
      check: (s) => auditInstalled(s.installed).length === 0 && testsGreenNow(scaLab, s),
    },
  ],
};
