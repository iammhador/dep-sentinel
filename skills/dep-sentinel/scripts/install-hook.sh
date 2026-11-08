#!/bin/sh
# dep-sentinel: install (or remove) a git pre-push hook that scans dependencies,
# lockfiles and outgoing commits before every push.
#
#   install-hook.sh                 install in the current git repository
#   install-hook.sh --gate critical block only on critical (default: high)
#   install-hook.sh --uninstall     remove it and restore any previous hook
#
# The scanner is copied into .git/dep-sentinel/, so nothing in the repository
# changes and the hook keeps working when the skill is updated or moved.
# Re-run this script after updating the skill to refresh the copy.
set -eu

SRC=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
GATE=high
ACTION=install
while [ $# -gt 0 ]; do
  case "$1" in
    --uninstall) ACTION=uninstall ;;
    --gate) GATE=${2:?--gate needs low|moderate|high|critical}; shift ;;
    --gate=*) GATE=${1#--gate=} ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "dep-sentinel: unknown option $1" >&2; exit 64 ;;
  esac
  shift
done
case "$GATE" in low|moderate|high|critical) ;; *) echo "dep-sentinel: --gate must be low, moderate, high or critical" >&2; exit 64 ;; esac

git rev-parse --git-dir >/dev/null 2>&1 || { echo "dep-sentinel: run this inside a git repository" >&2; exit 1; }
TOP=$(git rev-parse --show-toplevel)
COMMON=$(cd "$TOP" && cd "$(git rev-parse --git-common-dir)" && pwd)
HOOKS=$(cd "$TOP" && git rev-parse --git-path hooks)
case "$HOOKS" in /*) ;; *) HOOKS="$TOP/$HOOKS" ;; esac
HOME_DIR="$COMMON/dep-sentinel"
MARK="# dep-sentinel pre-push hook"
# An `if` (not `[ ] &&`) so the line exits 0 for teammates without dep-sentinel.
# shellcheck disable=SC2016  # written literally into .husky/pre-push, expanded there
HUSKY_LINE='if [ -x "$(git rev-parse --git-common-dir)/dep-sentinel/pre-push" ]; then "$(git rev-parse --git-common-dir)/dep-sentinel/pre-push" "$@" || exit $?; fi'

hooks_path=$(git config --get core.hooksPath || true)
case "$hooks_path" in
  *.husky|*.husky/|*.husky/_|*.husky/_/) MODE=husky ;;
  *) MODE=plain ;;
esac
if [ -f "$TOP/lefthook.yml" ] || [ -f "$TOP/.lefthook.yml" ] || [ -f "$TOP/lefthook.yaml" ]; then MODE=lefthook; fi

if [ "$ACTION" = uninstall ]; then
  if [ -f "$HOOKS/pre-push" ] && grep -q "$MARK" "$HOOKS/pre-push"; then
    rm -f "$HOOKS/pre-push"
    [ -f "$HOOKS/pre-push.before-dep-sentinel" ] && mv "$HOOKS/pre-push.before-dep-sentinel" "$HOOKS/pre-push"
  fi
  if [ -f "$TOP/.husky/pre-push" ] && grep -q "dep-sentinel/pre-push" "$TOP/.husky/pre-push"; then
    grep -v "dep-sentinel" "$TOP/.husky/pre-push" > "$TOP/.husky/pre-push.tmp" && mv "$TOP/.husky/pre-push.tmp" "$TOP/.husky/pre-push"
    chmod +x "$TOP/.husky/pre-push"
  fi
  rm -rf "$HOME_DIR"
  echo "dep-sentinel: pre-push hook removed."
  exit 0
fi

# 1) Private copy of the scanner + the runner the hook calls.
mkdir -p "$HOME_DIR"
cp "$SRC/scan.py" "$SRC/scan.sh" "$HOME_DIR/"
chmod +x "$HOME_DIR/scan.sh" "$HOME_DIR/scan.py"
printf '%s\n' "$GATE" > "$HOME_DIR/gate"

cat > "$HOME_DIR/pre-push" <<'RUNNER'
#!/bin/sh
# dep-sentinel pre-push runner. Exit 1 stops the push.
# Skip once:  DEP_SENTINEL_SKIP=1 git push   (or: git push --no-verify)
[ "${DEP_SENTINEL_SKIP:-0}" = "1" ] && exit 0
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(git rev-parse --show-toplevel)
GATE=${DEP_SENTINEL_GATE:-$(cat "$HERE/gate" 2>/dev/null || echo high)}
Z=0000000000000000000000000000000000000000

# Secret-scan only the commits being pushed.
set --
while read -r _local_ref local_sha _remote_ref remote_sha; do
  case "$local_sha" in ""|"$Z"|0000000000000000000000000000000000000000000000000000000000000000) continue ;; esac
  case "$remote_sha" in
    "$Z"|0000000000000000000000000000000000000000000000000000000000000000) set -- "$@" --secrets-range "$local_sha --not --remotes" ;;
    *) set -- "$@" --secrets-range "$remote_sha..$local_sha" ;;
  esac
done
[ $# -eq 0 ] && exit 0  # nothing to push (e.g. only deleting a branch)

"$HERE/scan.sh" --dir "$ROOT" --gate "$GATE" --quiet --report "$HERE/last-report.json" "$@"
code=$?
case $code in
  0) echo "dep-sentinel: no known vulnerabilities, secrets or lockfile problems." ; exit 0 ;;
  1) echo "dep-sentinel: warnings above (below the '$GATE' gate), push allowed." ; exit 0 ;;
  2) ;;
  *) echo "dep-sentinel: scanner failed (exit $code); push allowed. Run $HERE/scan.sh to investigate." >&2 ; exit 0 ;;
esac

echo ""
echo "dep-sentinel: push blocked. Fix the issues above, or skip once with: git push --no-verify"
if [ "${DEP_SENTINEL_NO_CLAUDE:-0}" != "1" ] && command -v claude >/dev/null 2>&1 && (exec </dev/tty) 2>/dev/null; then
  printf "dep-sentinel: fix them with Claude now? [Y/n] " >/dev/tty
  read -r answer </dev/tty || answer=n
  case "$answer" in
    ""|y|Y|yes|YES)
      claude "Use the dep-sentinel skill in fix mode: this git push was blocked by its pre-push check. The full scan report is at $HERE/last-report.json. Follow this project's rules (CLAUDE.md / AGENTS.md), work on a new branch, and do not commit or push; give me the commit message when done." </dev/tty >/dev/tty 2>&1
      echo "dep-sentinel: review Claude's changes, commit them, then push again." ;;
  esac
fi
exit 1
RUNNER
chmod +x "$HOME_DIR/pre-push"

# 2) Wire the runner into the repository's hooks.
case "$MODE" in
  husky)
    HFILE="$TOP/.husky/pre-push"
    if [ -f "$HFILE" ] && grep -q "dep-sentinel/pre-push" "$HFILE"; then :; else
      [ -f "$HFILE" ] || printf '' > "$HFILE"
      printf '%s\n' "$HUSKY_LINE" >> "$HFILE"
      chmod +x "$HFILE"
    fi
    echo "dep-sentinel: added to .husky/pre-push (it only runs where dep-sentinel is installed, so teammates are unaffected)."
    ;;
  lefthook)
    echo "dep-sentinel: Lefthook detected. Add this to lefthook.yml, then run 'lefthook install':"
    echo ""
    echo "pre-push:"
    echo "  commands:"
    echo "    dep-sentinel:"
    echo "      run: '$HOME_DIR/pre-push'"
    echo "      use_stdin: true"
    ;;
  plain)
    mkdir -p "$HOOKS"
    if [ -f "$HOOKS/pre-push" ] && ! grep -q "$MARK" "$HOOKS/pre-push"; then
      mv "$HOOKS/pre-push" "$HOOKS/pre-push.before-dep-sentinel"
      echo "dep-sentinel: your existing pre-push hook was kept and still runs first."
    fi
    cat > "$HOOKS/pre-push" <<HOOK
#!/bin/sh
$MARK (remove with: install-hook.sh --uninstall)
input=\$(cat)
if [ -x "\$(dirname "\$0")/pre-push.before-dep-sentinel" ]; then
  printf '%s\n' "\$input" | "\$(dirname "\$0")/pre-push.before-dep-sentinel" "\$@" || exit \$?
fi
[ -x "$HOME_DIR/pre-push" ] || exit 0
printf '%s\n' "\$input" | "$HOME_DIR/pre-push" "\$@"
HOOK
    chmod +x "$HOOKS/pre-push"
    ;;
esac

echo "dep-sentinel: pre-push check installed (blocks at '$GATE' and above). Scanner: $HOME_DIR"
