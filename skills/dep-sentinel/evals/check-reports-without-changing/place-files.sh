#!/usr/bin/env bash
set -eu
cp -R "$(dirname "$0")/files/." .
git init -q 2>/dev/null || true
git add -A >/dev/null 2>&1 || true
git -c user.email=eval@example.com -c user.name=eval commit -qm fixture >/dev/null 2>&1 || true
