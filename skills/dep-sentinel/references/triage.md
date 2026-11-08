# Triage: deciding what a finding really means

Read this when a finding's real risk is unclear, before ignoring anything, or when tools disagree.

## Contents
1. Four questions per finding
2. Severity
3. Runtime vs dev-only
4. False positives
5. When tools disagree
6. When to ignore (and how)

## 1. Four questions per finding

1. **Is the vulnerable version actually installed?** Advisories list *affected ranges*; check the installed version in the lockfile (`scan.sh` reports both). Ranges like `<1.1.17` alone are not proof.
2. **Does it ship to production?** A build-time linter dependency cannot be attacked by a website visitor; a server-side parser can.
3. **Is the vulnerable code reachable?** A ReDoS in a function your app never calls with untrusted input is lower risk. `govulncheck` reports reachability for Go; elsewhere, search the code for the affected API (the advisory names it).
4. **Who controls the input?** Anonymous internet > logged-in users > admins > build-time constants. The same bug is critical in a public upload endpoint and minor in a CLI flag.

Answering these turns a list of 40 "high" findings into the 3 that matter today. Fix those first, but still fix the rest when it is cheap (usually it is: one `audit fix`).

## 2. Severity

- Tools label severity from CVSS or their own database. Treat it as a starting point and adjust with the four questions; say when you do.
- **Unknown severity** (pip-audit, some Go and Cargo advisories): `scan.sh` looks it up on OSV.dev. If still unknown, treat it as high until you have read the advisory.
- **Severity mismatch between tools**: report the highest, and note the difference.

## 3. Runtime vs dev-only

How to tell:
- **npm/bun/pnpm/yarn:** is the package under `dependencies` or `devDependencies`? For transitive ones, ask which top-level package pulls it in (`npm ls <pkg>`, `bun why <pkg>`, `pnpm why <pkg>`, `yarn why <pkg>`).
- **Python:** main group vs dev/test groups in `pyproject.toml`; `requirements-dev.txt`.
- **Cargo:** `[dev-dependencies]` / `[build-dependencies]`.

Dev-only does not mean ignore. Compromised build tools (malicious packages, CI secrets) are a real attack path, and dev findings still break "clean" gates. It means **lower priority**, and fixing through the normal upgrade is fine.

Bundlers blur the line: a "devDependency" bundled into the browser build *is* runtime code. Frameworks such as Next.js, Vite and webpack bundle libraries that are listed as dev dependencies.

## 4. False positives

Common, legitimate cases:
- **Fixed outside the registry.** For example, SheetJS (`xlsx`) publishes fixed versions only on its own CDN, so npm-based databases flag every version. Verify the advisory says which version fixes it and that you install that version (from the vendor URL), then ignore with that reason.
- **Withdrawn or disputed advisories.** The advisory page says "withdrawn"; databases lag behind.
- **Backported fixes.** Distribution packages and vendored forks may patch without changing the version number.
- **Wrong package matched.** Name collisions across ecosystems, or a scoped package confused with an unscoped one.

Always link the evidence (advisory page, changelog line) in the ignore reason. "False positive" without proof is not acceptable.

## 5. When tools disagree

Different databases, different files:
- **Snyk** reads `package-lock.json` (or `node_modules` + `package.json`). It does not understand every lockfile format, so with Bun or pnpm it can miss transitive packages.
- **npm/bun/pnpm audit** use the GitHub Advisory Database.
- **OSV** aggregates GitHub, PyPA, RustSec, Go and more.

Treat the union as the truth. A package only one tool flags is still a finding. Stale extra lockfiles (a `package-lock.json` next to `bun.lock`) make tools scan the wrong versions. Remove lockfiles of package managers the project does not use, after confirming CI/deploy doesn't use them.

## 6. When to ignore (and how)

Ignore only when:
- no fixed version exists **and** you mitigated or confirmed the risk does not apply, or
- it is a proven false positive.

Requirements:
- **A reason that a stranger can verify:** what makes it safe, plus a link.
- **An expiry of 3–6 months** so it is re-checked. Expired ignores count again automatically.
- **Recorded in the project's existing policy file**, or `.dep-sentinel-ignore`. Use the IDs every tool reports: GHSA/CVE as well as tool-specific ones such as SNYK-JS-… when Snyk is used.

Never ignore just to make a push go through. `git push --no-verify` exists for emergencies, and it leaves no permanent hole.
