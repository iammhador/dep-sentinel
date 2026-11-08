# dep-sentinel

**Dependency security for any project, with Claude doing the fixing.**

dep-sentinel finds known vulnerabilities in your dependencies with **every scanner you have**, catches **lockfiles that drifted** from their manifests, and spots **leaked secrets**. Then it fixes them safely and proves the fix works. A fast **pre-push check** blocks risky pushes and offers to hand the fix to Claude.

### Why

One scanner is not enough. On a real project:
- **Snyk** reported "no vulnerable paths", while **`bun audit`** found 26 issues (20 high) in transitive packages.
- A `package.json` change without a matching `bun.lock` update would have **broken every deploy**.
- Two pages ran injected script because HTML was cleaned only on save.

Nobody noticed any of it until someone ran the right tool by hand. dep-sentinel runs all of them, every time.

## What it checks

| Check | How |
|---|---|
| Known vulnerabilities | Every installed native auditor (table below), plus **OSV-Scanner** as a cross-check. Results are merged and de-duplicated across tools. Missing severities are filled from [OSV.dev](https://osv.dev). |
| Lockfile drift | npm (the same check `npm ci` does), bun, pnpm, Cargo, Go, Poetry, uv, Composer |
| Leaked secrets | gitleaks if installed, otherwise built-in patterns (private keys, AWS/GitHub/GitLab/Slack/Stripe/Google/OpenAI/npm/SendGrid tokens, credentials in URLs). Committed `.env` files also count. |
| Code-level risks | Claude's checklist: XSS sinks, SQL/shell injection, auth-before-write, secrets in client bundles, unsafe parsing of uploads |

| Ecosystem | Detected from | Scanner used (if installed) |
|---|---|---|
| JavaScript / TypeScript | `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock` | `npm audit`, `pnpm audit`, `yarn audit` / `yarn npm audit`, `bun audit` |
| Python | `requirements*.txt` (+ OSV for `poetry.lock`, `uv.lock`, `Pipfile.lock`) | `pip-audit` (or via `uvx` / `pipx`) |
| Rust | `Cargo.lock` | `cargo audit` |
| Go | `go.mod` | `govulncheck` (reachability-aware) |
| PHP | `composer.lock` | `composer audit` |
| Ruby | `Gemfile.lock` | `bundle-audit` |
| .NET | `*.csproj` / `*.fsproj` | `dotnet list package --vulnerable` |
| Everything above + Java, Dart, Elixir, … | any lockfile OSV supports | `osv-scanner` |

Tools that aren't installed are reported as **skipped**, never as "safe".

## Install

**Claude Code (plugin marketplace)**
```
/plugin marketplace add iammhador/dep-sentinel
/plugin install dep-sentinel@dep-sentinel
```

**Manual (any Claude Code setup):** copy `skills/dep-sentinel` to `~/.claude/skills/dep-sentinel` (every project), or to `.claude/skills/dep-sentinel` inside one project.

**Claude.ai / Claude Desktop:** zip the `skills/dep-sentinel` folder and upload it under *Settings → Capabilities → Skills*.

**Requirements:** Python 3.8+ (standard library only) and git. Scanners are optional: install the ones for your stack. OSV-Scanner and gitleaks give the widest coverage.

## Use

Just ask Claude:
- "Check this project for vulnerabilities."
- "Snyk found 20 issues, fix them."
- "There's a new Next.js security advisory, are we affected?"
- "Set up a security check before every push."

Claude runs the scanner, triages each finding (is it installed? shipped to production? reachable? who controls the input?), fixes in a safe order, verifies, and reports:
- **safe order:** in-range upgrades → transitive fixes → majors (after reading the changelog) → documented ignores, only when no fix exists
- **release-age rule:** prefers releases at least 14 days old
- **verification:** frozen install, lint, tests, build, real checks of the upgraded code, rescan

It follows your repo's rules (CLAUDE.md / AGENTS.md), works on a new branch, and won't commit or push unless you ask.

## Pre-push check

From the root of any git repository:
```bash
~/.claude/skills/dep-sentinel/scripts/install-hook.sh   # or ask Claude: "install the dep-sentinel pre-push hook"
```

- **Clean push:** one line, continues. It typically takes under a second for JS projects.
- **High or critical finding, secret, or lockfile drift:** the push is blocked with the findings. In a terminal with Claude Code installed you get *"fix them with Claude now? [Y/n]"*.
- **Bypass once:** `git push --no-verify` or `DEP_SENTINEL_SKIP=1 git push`.
- **Change the threshold:** `install-hook.sh --gate critical`, or `DEP_SENTINEL_GATE=moderate`.
- **Remove it:** `install-hook.sh --uninstall`.

It keeps your existing `pre-push` hook (and runs it first), works with Husky (adds a line that's a no-op for teammates without dep-sentinel), prints a snippet for Lefthook, and only scans the commits you're pushing for secrets. The scanner is copied into `.git/dep-sentinel/`, so your repository doesn't change.

## Run the scanner directly (CI, scripts)

```bash
skills/dep-sentinel/scripts/scan.sh                 # human-readable report
skills/dep-sentinel/scripts/scan.sh --json          # machine-readable
skills/dep-sentinel/scripts/scan.sh --gate critical --report out.json
```

| Exit code | Meaning |
|---|---|
| `0` | Clean |
| `1` | Warnings only: findings below the gate, or something couldn't be scanned |
| `2` | Blocking: a finding at or above the gate (default `high`), a secret, or a lockfile out of sync |

Other flags: `--dir`, `--unknown-as`, `--no-secrets`, `--no-lockfile`, `--no-osv`, `--offline`, `--secrets-range <git range>`.

## Ignoring a finding (with an expiry)

dep-sentinel honours `.snyk`, `.osv-scanner.toml`, and its own `.dep-sentinel-ignore`:
```
GHSA-xxxx-xxxx-xxxx  expires=2027-05-08  reason=no fixed version; input is admin-only and sanitized server-side
```
Expired ignores count again automatically, so nothing stays hidden forever.

## Privacy

- Scans run locally.
- To fill in missing severities, dep-sentinel sends **advisory IDs only** (e.g. `GHSA-…`, `PYSEC-…`) to `api.osv.dev`. Use `--offline` to disable this.
- Native auditors contact their own registries, exactly as when you run them yourself.
- Secrets that are found are masked in all output.

## License

MIT
