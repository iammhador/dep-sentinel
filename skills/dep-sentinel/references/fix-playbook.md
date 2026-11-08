# Fix playbook: commands per ecosystem

Read the section for the project's package manager. Always use the package manager that CI/deploy uses (check workflow files and the `packageManager` field), so the right lockfile changes.

## Contents
- JavaScript: npm · pnpm · yarn · bun
- Python: pip · Poetry · uv · Pipenv
- Rust · Go · PHP · Ruby · .NET · Java
- Checking release age
- After any change

## JavaScript

Find who pulls in a transitive package before forcing it:
`npm ls <pkg>` · `pnpm why <pkg>` · `yarn why <pkg>` · `bun why <pkg>`

**npm**
```bash
npm audit fix                 # in-range fixes (safe)
npm install <pkg>@<version>   # direct dependency
npm audit fix --force         # crosses majors: read the plan first, avoid by default
```
Transitive pin when the parent has no fix yet. In `package.json`:
`"overrides": { "<pkg>": "^1.2.3" }`, or scoped as `"overrides": { "parent": { "<pkg>": "^1.2.3" } }`.

**pnpm**
```bash
pnpm audit --fix              # writes pnpm.overrides for vulnerable transitive deps
pnpm update <pkg> --recursive
```
Overrides go in `package.json` → `"pnpm": { "overrides": { "<pkg>": "^1.2.3" } }`.

**yarn**
- Classic (v1): `yarn upgrade <pkg>@<version>`. Pin transitive deps with `"resolutions": { "<pkg>": "^1.2.3" }`, then run `yarn install`.
- Berry (v2+): `yarn up <pkg>`, or `yarn up -R <pkg>` for transitive deps. Resolutions go in `package.json`.

**bun**
```bash
bun audit fix                 # lowest safe version within existing ranges
bun audit fix --latest        # may cross majors: review first
bun add <pkg>@<version>
```
Bun also honours `"overrides"`.

**Packages not on the registry** (vendor-hosted fixes, e.g. SheetJS):
`bun add "xlsx@https://cdn.sheetjs.com/xlsx-0.20.3/xlsx-0.20.3.tgz"`. The same URL form works for npm, pnpm and yarn. Pin the exact version in the URL.

## Python

- **pip / requirements.txt:** bump the pin, then `pip install -r requirements.txt`. With pip-tools: `pip-compile --upgrade-package <pkg>`.
- **Poetry:** `poetry update <pkg>`, or `poetry add <pkg>@^X.Y` for a new range. Then `poetry check --lock`.
- **uv:** `uv lock --upgrade-package <pkg>`, then `uv sync`.
- **Pipenv:** `pipenv update <pkg>`.
- **Transitive pins:** add a constraint (`<pkg>>=X.Y`) to a constraints file, or to the dependency group (Poetry/uv), when the parent package lags behind.

## Rust
```bash
cargo update -p <crate>                # within semver range
cargo update -p <crate> --precise X.Y.Z
```
If the parent crate pins an old major, upgrade the parent, or use `[patch.crates-io]` as a last resort. Check with `cargo build --locked && cargo test`.

## Go
```bash
go get <module>@vX.Y.Z && go mod tidy
govulncheck ./...      # confirms the vulnerable symbol is no longer reachable
```
Go standard-library vulnerabilities are fixed by upgrading the Go toolchain: update the `go` / `toolchain` lines in go.mod.

## PHP
`composer update <vendor/pkg> --with-dependencies`, then `composer audit`. Commit `composer.lock`.

## Ruby
`bundle update --conservative <gem>`, then `bundle-audit check --update`.

## .NET
`dotnet add package <Id> --version X.Y.Z`. For transitive packages, reference the fixed version directly, or use Central Package Management with `<CentralPackageTransitivePinningEnabled>`.

## Java (Maven/Gradle)
Bump the version, or pin a transitive one through `<dependencyManagement>` (Maven) or `constraints {}` (Gradle). Verify with OSV-Scanner or the OWASP dependency-check plugin.

## Checking release age

```bash
npm view <pkg> time --json   # JS: publish date of every version
# PyPI:  https://pypi.org/pypi/<pkg>/json → releases[ver][0].upload_time
# Cargo: https://crates.io/api/v1/crates/<crate>/versions
```

Prefer the newest version that fixes the issue **and** is at least 14 days old. If a caret range (`^10.2.1`) would resolve to a release from yesterday, pin the exact version instead.

**Exception: data-only packages published daily by automation**, such as `caniuse-lite`, `electron-to-chromium`, `node-releases` and timezone/tzdata packages. When an upgraded parent requires a recent minimum, accept the new version and note it in the report. Pinning these through overrides makes the data go stale, and tools warn about outdated browser data. Check first that they only run at build time, not in the server or client bundle.

## After any change

1. Frozen install works:
   - `npm ci`
   - `pnpm install --frozen-lockfile`
   - `yarn install --immutable`
   - `bun install --frozen-lockfile`
   - `cargo build --locked`
   - `poetry check --lock` or `uv lock --check`
2. Lint, type-check, tests and build pass.
3. Exercise what the upgraded package does in this app.
4. Rescan with `scan.sh`. If a major version changed, read the migration notes once more against the code you touched.
