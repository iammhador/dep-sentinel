#!/bin/sh
# dep-sentinel: dependency, lockfile and secret scan. See scan.py --help.
# Thin wrapper so the scanner runs anywhere with Python 3.8+ (macOS, Linux, WSL, Git Bash).
DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
for py in python3 python; do
  if command -v "$py" >/dev/null 2>&1 && "$py" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null; then
    exec "$py" "$DIR/scan.py" "$@"
  fi
done
echo "dep-sentinel: Python 3.8+ is required (python3 not found)." >&2
exit 1
