#!/usr/bin/env bash
# `make merge PR=<n>`: squash-merge PR <n> under origin/main's merge rules (merge_rules.sh, whose
# header is the contract). Every repo's Makefile calls this one line, as it calls gate.sh:
#
#   merge: ; devkit/bin/pr_merge.sh "$(PR)"
#
# The rules and the plan they read are main's, never this checkout's: fetch_main, then run
# main's merge_rules.sh from main's copy of this directory (devkit/bin/ in a consumer, bin/ in
# devkit itself), extracted to a temp dir, with GATE_PLAN set to main's scripts/ci/gate_plan.sh,
# against this repo. Why (homelab #134, 2026-10-23): a checkout on a feature branch whose vendored
# devkit differed from main's ran that branch's rules, so any branch could change, or weaken, the
# rules its own or another PR merges under. The same principle as gate_plan_main and the gate's
# merged tree: what enforces is what main holds. A checkout whose devkit is NEWER than main's
# does not win either: a devkit change to the rules governs a repo's merges once it is on that
# repo's main, its own sync PR included.
# A caller's GATE_PLAN still wins, as for gate.sh (a plan outside the repo, the tests).
# Bootstrap: a main with no merge_rules.sh at this path (its devkit predates main-decided rules,
# or devkit's own main before 2026-10-23) has no rules to defer to, so this checkout's run, with
# one note line naming main. Nothing else falls back: a failed fetch, archive or a main with no
# plan is exit 2.
# Residual: this entry is the checkout's own. devkit-check holds a consumer's devkit/ to the
# devkit commit its .devkit-rev names, and every such commit since this one carries this entry.
# `--rules review_rules.sh` runs that script of main's the same way: `make review PR=<n>`
# (bin/pr_review.sh), whose record counts as a review round, so a branch must not choose its own
# reviewer either.
# Pinned main (its .devkit-rev, nothing tracked under devkit/): main's own .devkit-bootstrap.sh
# materializes main's pin into the temp dir, and that devkit/bin's rules decide; a refused pin or
# devkit unreachable is exit 2. Vendored, main's bin/ is extracted with the bootstrap template
# beside it (_vendor_paths.sh reads a pin's objects through it).
# Exit: merge_rules.sh's (0 merged, 1 refused, 2 usage or environment, else gh's own code).
set -uo pipefail

usage() { echo "usage: $0 [--rules review_rules.sh] <pr-number>"; }
RULES=merge_rules.sh
if [ "${1:-}" = --rules ] && [ "${2:-}" = review_rules.sh ]; then RULES=$2; shift 2; fi
[ $# -eq 1 ] || { usage >&2; exit 2; }
case "$1" in
  -h|--help) usage; exit 0 ;;
  ''|*[!0-9]*) usage >&2; exit 2 ;;
esac

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd) || exit 2
# shellcheck source=bin/_gate_env.sh  # fetch_main
. "$HERE/_gate_env.sh"
ROOT=$(git -C "$HERE" rev-parse --show-toplevel) || exit 2
# This directory's path in the repo: devkit/bin/ in a consumer, bin/ in devkit.
PREFIX=$(git -C "$HERE" rev-parse --show-prefix) || exit 2

fetch_main "$ROOT" || { echo "merge: cannot fetch origin main, whose rules decide the merge (git above)" >&2; exit 2; }
# The full ref: a local branch named origin/main would otherwise win.
MAIN=$(git -C "$ROOT" rev-parse --verify -q refs/remotes/origin/main) \
  || { echo "merge: no origin/main after the fetch" >&2; exit 2; }
PIN=$(git -C "$ROOT" show "$MAIN:.devkit-rev" 2>/dev/null) || PIN=''
if [ -n "$PIN" ] && [ -n "$(git -C "$ROOT" ls-tree --name-only "$MAIN" -- devkit)" ]; then PIN=''; fi
if [ -z "$PIN" ] && ! git -C "$ROOT" cat-file -e "$MAIN:${PREFIX}$RULES" 2>/dev/null; then
  echo "merge: origin/main ${MAIN:0:12} has no ${PREFIX}$RULES (its devkit predates main-decided rules); this checkout's rules decide"
  exec "$HERE/$RULES" "$ROOT" "$1"
fi

TMP=$(mktemp -d "${TMPDIR:-/tmp}/devkit-merge.XXXXXX") || exit 2
trap 'rm -rf "$TMP"' EXIT
if [ -n "$PIN" ]; then
  git -C "$ROOT" show "$MAIN:.devkit-bootstrap.sh" >"$TMP/bootstrap.sh" 2>/dev/null \
    || { echo "merge: origin/main ${MAIN:0:12} pins devkit but has no .devkit-bootstrap.sh" >&2; exit 2; }
  bash "$TMP/bootstrap.sh" --rev "${PIN%% *}" --tree "${PIN#* }" --into "$TMP/${PREFIX%/bin/}" \
    || { echo "merge: cannot materialize origin/main ${MAIN:0:12}'s devkit ${PIN:0:7} (above)" >&2; exit 2; }
else
  # Main's bin/, and the bootstrap template when main has one (a pin's objects are read through it).
  bootstrap=$(git -C "$ROOT" ls-tree --name-only "$MAIN" -- "${PREFIX%bin/}templates/bootstrap")
  git -C "$ROOT" archive "$MAIN" -- "$PREFIX" ${bootstrap:+"$bootstrap"} | tar -x -C "$TMP" \
    || { echo "merge: cannot extract ${PREFIX} of origin/main ${MAIN:0:12} (git above)" >&2; exit 2; }
fi
if [ -z "${GATE_PLAN:-}" ]; then
  git -C "$ROOT" show "$MAIN:scripts/ci/gate_plan.sh" >"$TMP/gate_plan.sh" 2>/dev/null \
    || { echo "merge: origin/main ${MAIN:0:12} has no scripts/ci/gate_plan.sh" >&2; exit 2; }
  export GATE_PLAN=$TMP/gate_plan.sh
fi
echo "merge: rules and plan from origin/main ${MAIN:0:12}"
"$TMP/${PREFIX}$RULES" "$ROOT" "$1"
