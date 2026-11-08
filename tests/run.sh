#!/usr/bin/env bash
# dep-sentinel test suite: checks real behaviour of scan.sh and install-hook.sh.
# Needs: bash, git, python3 (3.8+), npm (network access for `npm audit`).
#   tests/run.sh            run everything
#   tests/run.sh -v         also print scanner output on failure
set -u

REPO=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
SCAN="$REPO/skills/dep-sentinel/scripts/scan.sh"
HOOK="$REPO/skills/dep-sentinel/scripts/install-hook.sh"
FIXTURE="$REPO/skills/dep-sentinel/evals/check-reports-without-changing/files"
VERBOSE=${1:-}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.com GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.com
export DEP_SENTINEL_NO_CLAUDE=1 NO_COLOR=1

pass=0; fail=0
ok()   { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad()  { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [ -n "$VERBOSE" ] && [ -n "${2:-}" ] && printf '%s\n' "$2" | sed 's/^/        /'; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected $3, got $2)" "${4:-}"; fi; }
# json <file> <python expression over d>
json() { python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print($2)" "$1"; }
fresh() { rm -rf "${WORK:?}/${1:?}"; mkdir -p "$WORK/$1"; cd "$WORK/$1" && git init -q; }

echo "scan.sh"

# 1. clean project
fresh clean; echo "# hi" > README.md; git add -A; git commit -qm init
"$SCAN" --offline > out.txt 2>&1; check "clean project passes (exit 0)" $? 0 "$(cat out.txt)"

# 2. known-vulnerable npm package
fresh vuln; cp "$FIXTURE"/package*.json .; git add -A; git commit -qm init
"$SCAN" --json --report r.json > /dev/null 2>&1; code=$?
check "critical npm finding blocks (exit 2)" "$code" 2
check "finding names minimist" "$(json r.json "any(f['package']=='minimist' for f in d['findings'])")" True
check "finding carries a fixed version" "$(json r.json "any(f['fixed'] for f in d['findings'] if f['package']=='minimist')")" True
check "installed version read from lockfile" "$(json r.json "[f['version'] for f in d['findings'] if f['package']=='minimist'][0]")" 1.2.5
"$SCAN" --gate critical > /dev/null 2>&1; check "--gate critical still blocks a critical" $? 2

# 3. ignores with expiry
printf 'GHSA-xvch-5gv4-984h expires=2099-01-01 reason=test\n' > .dep-sentinel-ignore
"$SCAN" --json --report r.json --no-secrets > /dev/null 2>&1; check "valid ignore clears the gate (exit 0)" $? 0
check "ignored finding is still listed as ignored" "$(json r.json "d['summary']['ignored']")" 1
printf 'CVE-2021-44906 expires=2020-01-01 reason=old\n' > .dep-sentinel-ignore
"$SCAN" --json --report r.json --no-secrets > /dev/null 2>&1; check "expired ignore (by CVE alias) counts again" $? 2
check "expired ignore produces a warning" "$(json r.json "len(d['ignore_warnings'])")" 1
rm .dep-sentinel-ignore

# 4. lockfile drift
sed -i.bak 's/"minimist":"1.2.5"/"minimist":"1.2.8"/' package.json && rm -f package.json.bak
"$SCAN" --json --report r.json --no-secrets > /dev/null 2>&1; check "lockfile drift blocks (exit 2)" $? 2
check "drift reported for package-lock.json" "$(json r.json "d['summary']['lockfiles_out_of_sync']")" 1
git checkout -q -- package.json

# 5. secrets
fresh secrets
printf 'export const t = "%s%s";\nconst example = "AKIAEXAMPLE";\n' "ghp_" "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789" > leak.js
printf 'SECRET=1\n' > .env; printf 'SECRET=\n' > .env.example
git add -A; git commit -qm leak
"$SCAN" --json --report r.json --offline > /dev/null 2>&1; check "secrets block (exit 2)" $? 2
check "GitHub token found" "$(json r.json "any(s['type']=='GitHub token' for s in d['secrets'])")" True
check "token is masked in the report" "$(json r.json "all('aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789' not in s['match'] for s in d['secrets'])")" True
check "committed .env flagged" "$(json r.json "any(s['file']=='.env' for s in d['secrets'])")" True
check ".env.example and placeholders not flagged" "$(json r.json "any(s['file']=='.env.example' or 'EXAMPLE' in s['match'] for s in d['secrets'])")" False
git rm -q --cached .env; rm .env; git commit -qm cleanup -q; echo ok > more.txt; git add -A; git commit -qm more
"$SCAN" --json --report r.json --offline --secrets-range HEAD~1..HEAD > /dev/null 2>&1
check "range mode scans only the given commits" "$(json r.json "len(d['secrets'])")" 0

# 6. CVSS v3 scoring
check "CVSS 3.1 base score (9.8)" "$(python3 -c "import sys; sys.path.insert(0, '$REPO/skills/dep-sentinel/scripts'); import scan; print(scan.cvss3_score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'))")" 9.8
check "CVSS 3.1 scope-changed score (6.1)" "$(python3 -c "import sys; sys.path.insert(0, '$REPO/skills/dep-sentinel/scripts'); import scan; print(scan.cvss3_score('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'))")" 6.1

echo "install-hook.sh"

fresh hook; git init -q --bare "$WORK/remote.git"; git remote add origin "$WORK/remote.git"
echo "# app" > README.md; git add -A; git commit -qm init; git branch -M main
printf '#!/bin/sh\necho USER-HOOK-RAN\n' > .git/hooks/pre-push; chmod +x .git/hooks/pre-push
sh "$HOOK" > /dev/null 2>&1; check "installer succeeds" $? 0
out=$(git push -q origin main 2>&1); check "clean push allowed" $? 0 "$out"
case "$out" in *USER-HOOK-RAN*) ok "existing pre-push hook still runs" ;; *) bad "existing pre-push hook still runs" "$out" ;; esac
cp "$FIXTURE"/package*.json .; git add -A; git commit -qm vuln
out=$(git push origin main 2>&1); code=$?
if [ "$code" -ne 0 ]; then ok "vulnerable push blocked"; else bad "vulnerable push blocked" "$out"; fi
check "remote unchanged after block" "$(git ls-remote "$WORK/remote.git" main | cut -c1-7)" "$(git rev-parse --short HEAD~1)"
git push -q --no-verify origin main > /dev/null 2>&1; check "--no-verify bypasses" $? 0
sh "$HOOK" --uninstall > /dev/null 2>&1
check "uninstall restores the original hook" "$(grep -c USER-HOOK-RAN .git/hooks/pre-push)" 1
check "uninstall removes .git/dep-sentinel" "$([ -d .git/dep-sentinel ] && echo yes || echo no)" no

# Husky: the added line must be a no-op for teammates without dep-sentinel
fresh husky; mkdir -p .husky/_; git config core.hooksPath .husky/_; printf 'echo husky-step\n' > .husky/pre-push
sh "$HOOK" > /dev/null 2>&1; check "husky line added" "$(grep -c 'dep-sentinel/pre-push' .husky/pre-push)" 1
rm -rf .git/dep-sentinel
(cd .husky && sh ./pre-push < /dev/null > /dev/null 2>&1); check "husky line is a no-op without dep-sentinel (exit 0)" $? 0

echo ""
echo "passed: $pass  failed: $fail"
[ "$fail" -eq 0 ]
