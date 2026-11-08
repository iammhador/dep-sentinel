# Changelog

## Unreleased

- Eval cases moved to `evals/` at the repo root (`claude plugin eval` does not read cases inside `skills/`).
- Scanner skips test-fixture folders (`evals/`, `fixtures/`, `__fixtures__/`, `testdata/`, `test-fixtures/`), which are often intentionally vulnerable.
- Test suite (`tests/run.sh`, 30 behaviour tests) and GitHub Actions CI: Linux + macOS, Python 3.8 and 3.13, ShellCheck (including the generated hook), Ruff, vermin (3.8 compatibility), `claude plugin validate`.

## 1.0.0 — 2026-11-08

First public release.

- `scan.sh` / `scan.py`: multi-ecosystem vulnerability scan (npm, pnpm, yarn, bun, pip-audit, cargo audit, govulncheck, composer, bundle-audit, dotnet, OSV-Scanner), results merged across tools, missing severities filled from OSV.dev, lockfile drift checks, secret scan (gitleaks or built-in patterns), ignores with expiry (`.dep-sentinel-ignore`, `.snyk`, `.osv-scanner.toml`), exit codes for gating. Python 3.8+, standard library only.
- `install-hook.sh`: pre-push gate that keeps existing hooks, supports Husky (teammate-safe) and Lefthook, scans only outgoing commits for secrets, and offers to hand blocked pushes to Claude.
- `SKILL.md`: check / fix / install-hook workflows with triage, fix order, release-age rule and verification.
