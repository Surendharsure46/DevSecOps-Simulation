import { Brand } from '../components/Brand';
import { Ansi } from '../components/Ansi';
import { LABS, LEVELS } from '../content/labs';

const STEPS = [
  { icon: '⚙️', title: 'Configure pipelines', text: 'Write GitHub Actions workflows, wire security gates with needs:, and watch real runs pass or fail on exit codes.' },
  { icon: '🔍', title: 'Run security scans', text: 'Gitleaks, Semgrep, Trivy, Hadolint, Checkov, Kyverno and OWASP ZAP — from a terminal, against code you can change.' },
  { icon: '🛠️', title: 'Fix and validate', text: 'Edit the code, Dockerfile, Terraform and manifests. Re-scan and re-test to prove the fix — stale scans do not count.' },
  { icon: '🚀', title: 'Ship securely', text: 'Commit, push and deploy to staging through your gated pipeline, then attack the running app with DAST.' },
];

const TOOLS = ['git', 'npm', 'GitHub Actions', 'gitleaks', 'semgrep', 'trivy', 'syft', 'hadolint', 'docker', 'terraform', 'checkov', 'kubectl', 'kyverno', 'aws iam', 'curl', 'OWASP ZAP'];

const DEMO = `$ git push
remote: CI pipeline triggered → run #3
\x1b[31m✕ security\x1b[0m  semgrep scan --config auto --error
   ❯❯❱ node-postgres-sqli  src/routes/orders.js:9
\x1b[90m○ deploy    skipped (needs: security)\x1b[0m

$ git commit -am "Use parameterised query" && git push
\x1b[32m✓ build  ✓ security  ✓ deploy\x1b[0m
deployment "shopflow-api" successfully rolled out
\x1b[32m✔ Objective complete: gate proven and passing\x1b[0m`;

export function Welcome({ go, hasProgress }: { go: (r: string) => void; hasProgress: boolean }) {
  return (
    <div className="page">
      <nav className="topnav">
        <Brand onClick={() => go('/')} />
        <div style={{ display: 'flex', gap: 10 }}>
          {hasProgress && (
            <button className="btn ghost" onClick={() => go('/labs')}>
              My labs
            </button>
          )}
          <button className="btn primary" onClick={() => go('/start')}>
            Let&apos;s get started →
          </button>
        </div>
      </nav>

      <div className="wrap">
        <section className="hero">
          <div>
            <span className="chip green">Hands-on · no theory quizzes · runs in your browser</span>
            <h1>
              Welcome to the <span>Threatready DevSecOps Lab</span>
            </h1>
            <p className="lead">
              Work as the DevSecOps engineer at ShopFlow, a (fictional) online shop. Configure pipelines, run security scanners, investigate findings,
              fix vulnerabilities, verify the fix and ship to staging — with a real terminal, a real code editor and graded objectives that check what you
              actually did.
            </p>
            <div className="ctas">
              <button className="btn primary" onClick={() => go('/start')}>
                Let&apos;s get started →
              </button>
              {hasProgress && (
                <button className="btn" onClick={() => go('/labs')}>
                  Continue where I left off
                </button>
              )}
            </div>
          </div>
          <div className="termcard">
            <div className="bar">
              <i />
              <i />
              <i />
            </div>
            <pre>
              <Ansi text={DEMO} />
            </pre>
          </div>
        </section>

        <section className="section">
          <h2>What you will do</h2>
          <p className="sub">Every lab is a realistic ticket in a working repository. You execute, investigate, remediate and deploy — the lab checks the resulting state, not your answers.</p>
          <div className="grid4">
            {STEPS.map((s) => (
              <div className="card" key={s.title}>
                <div className="icon">{s.icon}</div>
                <h3>{s.title}</h3>
                <p>{s.text}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="section">
          <h2>Your learning path</h2>
          <p className="sub">{LABS.length} labs across five levels, from your first red build to an end-to-end secure release.</p>
          <div className="path">
            {LEVELS.map((l) => (
              <div className="card" key={l.level}>
                <div className="lvl">LEVEL {l.level}</div>
                <h3>{l.name}</h3>
                <p>{l.blurb}</p>
                <p style={{ marginTop: 8 }}>
                  {LABS.filter((x) => x.level === l.level).map((x) => (
                    <span key={x.id} style={{ display: 'block', color: '#cbd5e1' }}>
                      • {x.title}
                    </span>
                  ))}
                </p>
              </div>
            ))}
          </div>
        </section>

        <section className="section">
          <h2>Built for freshers and professionals</h2>
          <p className="sub">Pick how much help you want. You can switch any time.</p>
          <div className="grid3">
            <div className="card">
              <span className="chip green">Guided</span>
              <h3>Fresher</h3>
              <p>Step-by-step instructions, example commands you can run with one click, free hints and key concepts for each lab.</p>
            </div>
            <div className="card">
              <span className="chip blue">Standard</span>
              <h3>Practitioner</h3>
              <p>Objectives only. Hints are available but cost points. You decide the commands and the fix.</p>
            </div>
            <div className="card">
              <span className="chip violet">Expert</span>
              <h3>Professional</h3>
              <p>Just the ticket and acceptance criteria. No hints, a timer, troubleshooting traps and every lab unlocked.</p>
            </div>
          </div>
        </section>

        <section className="section">
          <h2>Toolchain you will use</h2>
          <div className="toolstrip">
            {TOOLS.map((t) => (
              <span key={t}>{t}</span>
            ))}
          </div>
        </section>
      </div>
      <div className="footer">All companies, people, credentials and data in this lab are fictional training material. Progress is stored only in this browser.</div>
    </div>
  );
}
