---
name: dep-sentinel
description: Finds and fixes known security vulnerabilities in a project's dependencies (npm, pnpm, yarn, bun, pip, Poetry, uv, Cargo, Go, Composer, Bundler, NuGet and more), lockfiles that no longer match their manifests, and leaked secrets, then upgrades and verifies safely. Use it whenever the user mentions vulnerabilities, CVEs, GHSA/Snyk/Dependabot/npm audit results, outdated or insecure packages, a security advisory for a framework they use (e.g. "a new Next.js security issue"), "is my project safe", a security check before pushing or deploying, or wants a pre-push security hook, even if they never say "dependency" or "audit". Also use it when a dep-sentinel pre-push check blocked a push.
---

# dep-sentinel

Keep a project's dependencies free of known vulnerabilities, its lockfiles in sync, and its history free of leaked secrets. Find problems with every scanner available, fix them safely, and prove the fix works.

One scanner is never enough. Snyk, npm/bun audit (GitHub advisories), OSV and the language-native tools each use different databases and read different files. In real projects one tool often reports "clean" while another finds a dozen high-severity issues. So scan with everything installed, and treat anything that could not be scanned as **unknown**, never as safe.

## Modes

- **check**: scan, triage, report. Change nothing. Use this when the user asks "is it safe", "any vulnerabilities", or similar.
- **fix**: the default when the user asks to fix, upgrade, patch or clean up, or when a pre-push check blocked a push. Scan, fix, verify, report.
- **install-hook**: set up the automatic pre-push check (see "Pre-push hook").

If the request is ambiguous, run **check** first, show the report, and offer to fix.

## The scanner

`scripts/scan.sh` (in this skill's folder) does the deterministic work in seconds and needs only Python 3.8+:

```bash
<skill-dir>/scripts/scan.sh --dir <project> --json --report /tmp/dep-sentinel.json
```

- It detects every ecosystem from lockfiles and manifests (monorepos included) and runs whichever native auditors are installed: npm/pnpm/yarn/bun audit, pip-audit (directly or through `uvx`/`pipx`), cargo audit, govulncheck, composer audit, bundle-audit, `dotnet list package --vulnerable`, and OSV-Scanner as a cross-check.
- It checks that lockfiles match their manifests, for npm, bun, pnpm, Cargo, Go, Poetry, uv and Composer. A mismatch breaks `npm ci` / `--frozen-lockfile` installs in CI and deploys.
- It scans for secrets with gitleaks if installed, otherwise built-in patterns. Tracked `.env` files also count.
- Missing severities are filled in from OSV.dev. Use `--offline` to skip that; unknown severity then counts as high.
- It honours ignores that carry an expiry, from `.dep-sentinel-ignore`, `.snyk` and `.osv-scanner.toml`.
- Exit codes: `0` clean, `1` warnings only (or something could not be scanned), `2` blocking. Blocking means a finding at or above `--gate` (default `high`), a secret, or a lockfile out of sync.

Read the JSON. `scanners` lists what ran, was skipped or errored, and `not_scanned` lists the blind spots. Mention both in your report, because a "pass" with no scanner run means nothing.

If the user already has results from another tool (a Snyk, Dependabot or `npm audit` report), merge those findings in too.

## Fix workflow

1. **Respect the project's rules first.** Read CLAUDE.md, AGENTS.md, CONTRIBUTING and similar files.
   - Work on a new branch unless the user says otherwise.
   - Do not commit or push unless the user asks. Many teams have strict rules about who commits.
   - Find the package manager actually used in CI/deploy (lockfile, `packageManager` field, workflow files). Upgrade with that one: fixing `package-lock.json` when deploys run `bun install --frozen-lockfile` leaves the real lockfile stale.

2. **Scan** with `scan.sh --json`, plus any project-configured tool (e.g. `snyk test` if `.snyk` exists and the CLI works).

3. **Triage every finding** before changing anything. Read `references/triage.md` when a call is unclear. It covers:
   - runtime vs dev/build-only
   - reachable vs not
   - false positives (for example fixes published outside the registry)
   - how to weigh severity

4. **Fix, in this order.** The exact commands per package manager are in `references/fix-playbook.md`.
   1. Patch/minor upgrades of direct dependencies.
   2. Transitive issues through the tool's fixer (`npm audit fix`, `bun audit fix`, `pnpm audit --fix`, `cargo update -p`) or overrides/resolutions/constraints.
   3. Major upgrades only after reading the changelog's breaking changes and searching the code for the APIs they touch.
   4. No fixed version anywhere: mitigate in code where the risk lives, then record an ignore **with a reason and an expiry date** (3–6 months) so it gets re-checked.

   **Release-age rule:** prefer versions published at least 14 days ago. Brand-new releases are where supply-chain attacks and regressions hide. Break this rule only when the fix exists only in a newer release, and say so.

5. **Look at the code around the risk** for anything the scanners cannot see: unsafe HTML rendering, SQL built from strings, writes before auth checks, secrets reaching client bundles. `references/code-checks.md` has a quick, stack-agnostic checklist. Read it when the project renders user or CMS content, or when a finding is mitigated rather than upgraded.

6. **Verify. Never stop at "the scanner is green".**
   - The lockfile installs frozen (`npm ci`, `bun install --frozen-lockfile`, `pnpm install --frozen-lockfile`, `cargo build --locked`, `poetry check --lock`, …).
   - Lint, type-check, tests and the production build pass.
   - Exercise the code paths that use the upgraded packages (send a test email after a mailer upgrade, round-trip a file after a parser upgrade, load the key pages).
   - Rescan with `scan.sh` until the gate passes. Every remaining finding must be documented.

7. **Report**, using the template below, then give a commit message if the user commits themselves.

## Report template

```markdown
## Security scan: <project>
Scanners: <ran> · Skipped: <skipped + why> · Not scanned: <blind spots or "none">

| Package | Before → After | Severity | Advisory | Status |
|---|---|---|---|---|
| nodemailer | 9.0.3 → 10.2.1 | high | GHSA-… (15 issues) | fixed |
| quill | 2.0.3 | moderate | GHSA-… | mitigated + ignored until 2027-05-08 (no fixed version) |

**Also found:** <lockfile problems, secrets, code-level issues>
**Verified:** <frozen install, lint, tests, build, manual checks>
**Remaining:** <each documented ignore with its reason, or "none">
```

Lead with the outcome ("clean: 0 blocking"), then the table. Use the user's own language and level; explain jargon like "transitive" the first time if the user isn't technical.

## Pre-push hook

`scripts/install-hook.sh` installs a git pre-push check in the current repository:

```bash
<skill-dir>/scripts/install-hook.sh            # block at high and above
<skill-dir>/scripts/install-hook.sh --gate critical
<skill-dir>/scripts/install-hook.sh --uninstall
```

- It copies the scanner into `.git/dep-sentinel/`, so nothing in the repository changes and the hook survives skill updates.
- It keeps any existing pre-push hook and runs it first, adds a teammate-safe line for Husky, and prints a snippet for Lefthook.
- It only secret-scans the commits being pushed.
- **Clean pushes** continue instantly.
- **Blocked pushes** show the findings and, in a terminal with Claude Code installed, ask "fix them with Claude now?". On yes it opens Claude with the report path, which brings you back to this skill in fix mode.
- Bypass once with `git push --no-verify` or `DEP_SENTINEL_SKIP=1`. Change the gate with `DEP_SENTINEL_GATE`.

After updating this skill, re-run `install-hook.sh` in each repo to refresh the copy.

When opened from a blocked push, the report is at `.git/dep-sentinel/last-report.json`. Start from it instead of rescanning blind, but still rescan after fixing.

## Ignore file format

Prefer the project's existing policy file (`.snyk`, `.osv-scanner.toml`). Otherwise use `.dep-sentinel-ignore` at the project root, one entry per line:

```
GHSA-xxxx-xxxx-xxxx  expires=2027-05-08  reason=no fixed version; input is admin-only and sanitized server-side
CVE-2024-12345       expires=2027-02-01  reason=false positive: fixed in vendor build 0.20.3 we install from the vendor CDN
```

Every ignore needs a real reason and an expiry. An ignore without one hides risk forever, which is how problems sit unnoticed for months.
