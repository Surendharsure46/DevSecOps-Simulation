# Threatready | DevSecOps Lab

A hands-on DevSecOps training lab that runs entirely in the browser. No login and no backend.
Learners work as the DevSecOps engineer at **ShopFlow**, a fictional online shop. They configure
pipelines, run security scanners, fix vulnerabilities, re-verify and ship to a simulated staging
cluster. Objectives are graded by checking the resulting state of the repository, pipeline and
environment, not by quizzes.

## Run it

```bash
npm install
npm run dev        # http://localhost:5180
npm run build      # type-check + production build into dist/
```

## Learner flow

Welcome page → **Let's get started** → choose a mode → lab dashboard → lab workspace.

| Mode | For | Support |
|---|---|---|
| Guided | freshers | step-by-step guidance, one-click example commands, free hints, key concepts; labs unlock in order |
| Standard | practitioners | objectives only; hints cost 5 points; labs unlock in order |
| Expert | professionals | ticket + acceptance criteria only, no hints, timer with speed bonus, all labs unlocked |

The workspace has:
- a task panel (briefing or ticket, objectives, hints)
- a file explorer and code editor
- a terminal with history, Tab completion, pipes and redirects
- a Findings view (results per tool, marked stale when the code changes after a scan)
- a GitHub-Actions-style Pipeline view with job graph and step logs
- Git and Activity tabs
- Commit & Push, Reset and a downloadable report

## Labs

| Level | Lab | What the learner actually does |
|---|---|---|
| 0 | Fix a red build | read CI logs, reproduce with `npm test`, fix real JS (tests execute the code), commit, push, get a green run |
| 1 | Credential committed to Git | `gitleaks git`, CloudTrail lookup, deactivate the IAM key, env-based config, `.gitignore`, `git filter-repo --replace-text`, re-add the remote, force-push, clean re-scan |
| 1 | Injection flaws in the Orders API | `semgrep scan`, parameterised queries, remove `eval()`, triage a false positive with a justified `nosemgrep`, re-scan + tests on the same code |
| 2 | Vulnerable dependencies | `trivy fs` / `npm audit`, upgrade without breaking (express 5 breaks the server), lockfile in sync, CycloneDX SBOM with `syft` |
| 2 | Harden the container image | `hadolint`, `docker build/run`, `trivy image`, minimal pinned base, non-root user, `.dockerignore`, no secrets in layers, container must still start |
| 3 | Terraform misconfigurations | `terraform init/validate/plan`, `checkov -d infra`, private and KMS-encrypted invoices bucket, SSH only from the VPN, private and encrypted DB, documented `#checkov:skip` for the intentionally public bucket |
| 3 | Build the security gate | edit `.github/workflows/ci.yml`, add gitleaks/semgrep/trivy gates, prove deploy is skipped, remove bypasses, remediate, ship green to staging |
| 4 | Capstone: ship ShopFlow securely | ZAP full scan of staging, close pipeline bypasses (`\|\| true`, exit-code 0, `fail_action`), helmet + cookie flags, image hardening, Kyverno-compliant manifest, green deploy, clean DAST evidence |

## How it works

`src/engine/` is a deterministic simulation of the toolchain. It works from the learner's actual
files, so results change when the code changes:

- `git.ts`: working tree, index, commits, remote, force-push, history rewrite
- `shell.ts`: the terminal command interpreter (git, npm, gitleaks, semgrep, trivy, syft, hadolint, docker, terraform, checkov, kubectl, kyverno, aws, curl, ZAP)
- `secrets.ts`, `sast.ts`, `sca.ts`, `container.ts`, `iac.ts`, `staging.ts`: the scanner rules, an offline advisory snapshot, the image build/run model, the Terraform/HCL checks, Kyverno admission and the DAST target
- `pipeline.ts`: a GitHub Actions subset (jobs, `needs`, `run`/`uses`/`with`, `if`, `continue-on-error`). It runs the same tool engine on the pushed commit, so gates behave like real exit codes.
- `lab.ts`: lab state, seeding, `settle()` (triggers CI on push and grades objectives) and scoring

Labs live in `src/content/labs/`, one file per lab. Each lab defines its seed history, tests and
objective checks. Progress is stored in `localStorage` only.

All companies, people, credentials and data are fictional training material.
