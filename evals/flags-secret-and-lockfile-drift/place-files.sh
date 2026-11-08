#!/usr/bin/env bash
set -eu
cp -R "$(dirname "$0")/files/." .
# The leaked token and the .env are generated here (not stored in the repo) so this
# fixture never trips GitHub push protection or dep-sentinel's own pre-push check.
mkdir -p src
printf 'export const token = "%s%s";\n' "ghp_" "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789" > src/config.js
printf 'DATABASE_URL=postgres://app:%s@db.internal:5432/app\n' "hunter2secret" > .env
git init -q 2>/dev/null || true
git add -A >/dev/null 2>&1 || true
git -c user.email=eval@example.com -c user.name=eval commit -qm fixture >/dev/null 2>&1 || true
