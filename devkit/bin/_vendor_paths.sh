# shellcheck shell=bash
# The VENDOR_PATHS manifest, applied to a git tree. Sourced; defines functions and DEVKIT_URL.
# Used by: devkit-sync.sh (filters upstream's tree before vendoring it), devkit-check.sh
# (a vendored tree must already be its own filtered form), hook_steps.sh and pr_merge.sh (what a
# vendoring-only change is) and dependency_merge.sh (the nightly sync). One code path, so the tree
# hash devkit-sync records in .devkit-rev is the hash every other reader recomputes.
#
# Every function reading tracked files takes <rev>: a commit, or "" for the index (the hooks and
# devkit-sync judge what is staged; pr_merge.sh and the nightly sync judge a PR's head).
#
# Two modes, per tree, until the last consumer migrates (devkit docs/plans/2026-11-13-stop-vendoring.md):
# VENDORED tracks devkit/ (its tree is .devkit-rev's); PINNED tracks only .devkit-rev and
# .devkit-bootstrap.sh, and devkit/ is an untracked directory the bootstrap materializes. A pin's
# own objects (its tree, its base copies' blobs) are read from the bootstrap's cache, never the
# consumer's object store, through this devkit's copy of the bootstrap (devkit_pin_git_dir).
#
#   devkit_pinned [<rev>]
#       True when <rev> records .devkit-rev and tracks nothing under devkit/: the pinned mode.
#
#   devkit_pin_git_dir <commit>
#       Print the cache's git dir once <commit> is in it (the bootstrap's --git-dir: it may
#       fetch; offline and uncached is its exit 2, passed on).
#
#   devkit_materialize <checkout>
#       In a pinned checkout, fill <checkout>/devkit from its .devkit-rev with this devkit's
#       bootstrap, as its own make would; a vendored one (or one without .devkit-rev) is left as
#       it is. Exit: 0, 1 the pin is refused (the commit's), 2 anything else (the box: devkit
#       unreachable, this devkit without its bootstrap, the bootstrap killed or not runnable).
#       Used by check_tree.sh, publish.sh's build and the nightly sync's worktrees.
#
#   devkit_pin_paths <old rev> <new rev>
#       "devkit/<path>", one per line, for each path the two pins' trees differ in, when <new
#       rev> is pinned and moved .devkit-rev: what a pin bump changes under devkit/, so a path
#       classifier (_paths_lib.sh) sees the devkit files a one-line bump moves. Nothing when
#       <old rev> is vendored: its devkit/ paths are already in the diff, as deletions. When <old rev>'s
#       pin is a commit devkit no longer has (bootstrap exit 1), every path of <new rev>'s tree.
#
#   DEVKIT_URL
#       Upstream, where devkit-sync fetches from (overridable, as tests do).
#
#   fetch_devkit_main <dir>
#       Fetch DEVKIT_URL's main into <dir>'s object store and print its commit. Into FETCH_HEAD,
#       no ref: a consumer clone keeps no devkit branch, so the single-branch refspec trap
#       fetch_main exists for (_gate_env.sh) cannot arise. Used by pr_merge.sh and the nightly sync.
#
#   swift_format_copies [<rev>]
#       The repo's tracked .swift-format files (root or nested), one per line.
#       devkit-check holds each byte-equal to lint/swift-format.json; devkit-sync refreshes them.
#
#   base_copies [<rev>]
#       "<base path in devkit> <repo path>" for each tracked file that must be a byte copy of a
#       vendored base: every swift_format_copies line, and .githooks/<hook> for each hook in
#       templates/githooks (the monthly audit's hook-differs), tracked or not once the repo
#       tracks any of them (devkit-sync.sh then creates it); pinned, .devkit-bootstrap.sh too.
#       The hook names come from devkit/ in a vendored tree, the pin's commit in the cache in a
#       pinned one. Read by devkit-sync.sh.
#
#   vendor_filter_tree <tree> <manifest text>
#       Print the hash of a tree holding only <tree>'s entries under the manifest's paths (modes,
#       symlinks and blobs unchanged), built in a throwaway index so the caller's is untouched.
#       A manifest path that matches nothing in <tree> is an error (exit status 2): a renamed
#       directory must not silently drop out of every consumer.
#
#   vendor_tree_of <commit>
#       The tree devkit-sync vendors from upstream <commit>: its VENDOR_PATHS filter of the
#       commit's tree, or the whole tree for a commit before the manifest (2026-10-13).
#
#   vendoring_only <rev> <paths>
#       True when <paths> (one per line) only vendor devkit at <rev>, as devkit-sync's own
#       commit does: every path is under devkit/, is .devkit-rev, or is a base copy
#       byte-identical to its base at <rev> and of its mode (a chmod -x of a hook copy disables it), and devkit/ at <rev> is the tree .devkit-rev records.
#       Pinned ("pin only"): every path is .devkit-rev or a base copy equal to its base at the
#       pinned commit, and the pinned tree is that commit's filtered tree (both in the cache).
#       Sets VENDORED_TREE. A hand edit under devkit/ breaks the hash; it proves nothing about
#       where the tree came from (vendored_from does).
#
#   vendored_from <rev> <upstream> [<base rev>]
#       True when <rev>'s .devkit-rev names a commit <upstream> contains and the tree recorded
#       is vendor_tree_of that commit, so devkit/ (once vendoring_only holds) is upstream's own
#       reviewed code and not a hand edit recorded as a sync; with <base rev>, also a commit that
#       contains <base rev>'s vendored one (a sync forward, never back). Needs <upstream>'s
#       objects: `git fetch "$DEVKIT_URL" main` first.
#
#   devkit_sync_only <rev> <base> <paths>
#       True when <paths> are a devkit sync at <rev>: every path but VENDOR_SYNC_BOUNDS passes
#       vendoring_only (at least one must), and that bounds file, when listed, differs from
#       <base>'s copy only by tightened bounds (metrics_ratchet.py tightens). Why (devkit decisions
#       2026-10-28): a sync may lock in the gains a devkit collector change measures, and a
#       tightening can only make the ratchet stricter. Used where vendoring_only decided alone: the
#       hooks' skip, make merge's Codex exemption and the nightly sync's own checks. <base> is a
#       commit (never "" here); the bounds check needs the caller's devkit_python
#       (bin/_toolchain_lib.sh), run only when the file is listed. Sets VENDORED_TREE.

DEVKIT_URL=${DEVKIT_URL:-https://github.com/kashhq/devkit.git}
VENDOR_SYNC_BOUNDS=docs/metrics/ratchet.json
# Resolved now: callers run these functions from inside a subshell that cd'd to the repo.
_VENDOR_PATHS_BIN=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# This devkit's bootstrap (VENDOR_PATHS lists templates/bootstrap; pr_merge.sh extracts it beside
# main's bin/), whose bytes every pinned consumer's .devkit-bootstrap.sh holds.
DEVKIT_BOOTSTRAP=$_VENDOR_PATHS_BIN/../templates/bootstrap/devkit-bootstrap.sh
BOOTSTRAP_BASE=templates/bootstrap/devkit-bootstrap.sh
BOOTSTRAP_COPY=.devkit-bootstrap.sh

vendor_filter_tree() { # <tree> <manifest text>
  local tree=$1 line path index status=0
  local paths=()
  while IFS= read -r line || [ -n "$line" ]; do
    line=${line%%#*}
    line=${line//[[:space:]]/}
    [ -n "$line" ] || continue
    case "$line" in
      /*|*..*|*'*'*|*'?'*|*'['*) echo "VENDOR_PATHS: '$line' must be a plain relative path" >&2; return 2 ;;
    esac
    path=${line%/}
    if [ -z "$(git ls-tree -r --name-only "$tree" -- "$path" | head -1)" ]; then
      echo "VENDOR_PATHS: '$path' matches nothing in tree ${tree:0:7}" >&2
      return 2
    fi
    paths+=("$path")
  done <<<"$2"
  [ "${#paths[@]}" -gt 0 ] || { echo "VENDOR_PATHS: no paths listed" >&2; return 2; }
  index=$(mktemp "${TMPDIR:-/tmp}/vendor-index.XXXXXX")
  rm -f "$index"   # git refuses an empty file as an index; it creates its own
  git ls-tree -r "$tree" -- "${paths[@]}" | GIT_INDEX_FILE=$index git update-index --index-info \
    && GIT_INDEX_FILE=$index git write-tree || status=2
  rm -f "$index"
  return "$status"
}

fetch_devkit_main() { # <dir>
  git -C "$1" fetch -q --no-tags "$DEVKIT_URL" main && git -C "$1" rev-parse FETCH_HEAD
}

# _vendor_entry <rev> <path>: "<mode> <blob>" of <path> at <rev>, or in the index for "".
_vendor_entry() {
  if [ -z "$1" ]; then
    git ls-files -s -- "$2" | awk '{ print $1, $2 }'
  else
    git ls-tree "$1" -- "$2" | awk '{ print $1, $3 }'
  fi
}

# _vendor_files <rev>: every path tracked at <rev>, or in the index when <rev> is "".
_vendor_files() {
  if [ -z "$1" ]; then git ls-files; else git ls-tree -r --name-only "$1"; fi
}

# _vendor_record <rev>: .devkit-rev's line at <rev> (the index for "").
_vendor_record() { git show "${1:-}:.devkit-rev" 2>/dev/null; }

devkit_pinned() { # [<rev>]
  _vendor_record "${1:-}" >/dev/null || return 1
  if [ -z "${1:-}" ]; then
    [ -z "$(git ls-files -- devkit | head -1)" ]
  else
    [ -z "$(git ls-tree --name-only "$1" -- devkit)" ]
  fi
}

devkit_pin_git_dir() { # <commit>
  bash "$DEVKIT_BOOTSTRAP" --git-dir --rev "$1"
}

devkit_materialize() { # <checkout>
  local record rc=0
  [ -z "$(git -C "$1" ls-files -- devkit | head -1)" ] || return 0
  record=$(git -C "$1" show HEAD:.devkit-rev 2>/dev/null) || return 0
  [ -f "$DEVKIT_BOOTSTRAP" ] || {
    echo "devkit: this devkit ($_VENDOR_PATHS_BIN) has no ../$BOOTSTRAP_BASE, so it cannot materialize a pin" >&2
    return 2
  }
  bash "$DEVKIT_BOOTSTRAP" --rev "${record%% *}" --tree "${record#* }" --into "$1/devkit" || rc=$?
  # Only the bootstrap's own refusal (1) is the commit's; it not running at all is the box's.
  case $rc in 0|1) return "$rc" ;; *) return 2 ;; esac
}

devkit_pin_paths() { # <old rev> <new rev>
  local old new gd old_tree new_tree rc=0
  devkit_pinned "$2" && devkit_pinned "$1" || return 0
  old=$(_vendor_record "$1") && new=$(_vendor_record "$2") || return 1
  [ "$old" != "$new" ] || return 0
  gd=$(devkit_pin_git_dir "${new%% *}") || return 1
  # The old pin is the last published commit's, fixed: a devkit that no longer has it (a
  # force-pushed branch) would fail here every cycle and stall publishing. Confirmed gone (the
  # bootstrap's 1) means every devkit path may have changed; any other failure is the box's.
  gd=$(devkit_pin_git_dir "${old%% *}") || rc=$?
  if [ "$rc" = 1 ]; then
    echo "devkit: ${old%% *} (the old pin) is gone from devkit; counting every devkit/ path as changed" >&2
    gd=$(devkit_pin_git_dir "${new%% *}") || return 1
    new_tree=$(GIT_DIR=$gd vendor_tree_of "${new%% *}") || return 1
    GIT_DIR=$gd git ls-tree -r --name-only "$new_tree" | sed 's|^|devkit/|'
    return 0
  fi
  [ "$rc" = 0 ] || return "$rc"
  # The commits' filtered trees, as each pin records them (vendor_tree_of writes them into the
  # cache, where the bootstrap only ever hashed them in a scratch store).
  old_tree=$(GIT_DIR=$gd vendor_tree_of "${old%% *}") && new_tree=$(GIT_DIR=$gd vendor_tree_of "${new%% *}") || return 1
  GIT_DIR=$gd git diff-tree -r --no-renames --name-only "$old_tree" "$new_tree" | sed 's|^|devkit/|'
}

swift_format_copies() { # [<rev>]
  _vendor_files "${1:-}" | awk '/(^|\/)\.swift-format$/'
}

base_copies() { # [<rev>]
  local rev=${1:-} files copy hook record gd
  while IFS= read -r copy; do
    [ -z "$copy" ] || echo "lint/swift-format.json $copy"
  done <<<"$(swift_format_copies "$rev")"
  # The template names come from the repo's own vendored devkit/ (in the index, the tree a sync
  # has just replaced), or its pin's commit in the cache. A repo that tracks one hook copy has
  # adopted the hooks, so a hook upstream adds is listed too and the sync creates it; a repo with
  # none gets none.
  local templates adopted=0
  files=$(_vendor_files "$rev")
  if devkit_pinned "$rev"; then
    echo "$BOOTSTRAP_BASE $BOOTSTRAP_COPY"
    record=$(_vendor_record "$rev") && gd=$(devkit_pin_git_dir "${record%% *}") || return 1
    templates=$(GIT_DIR=$gd git ls-tree --name-only "${record%% *}" -- templates/githooks/)
  else
    templates=$(awk '/^devkit\/templates\/githooks\//' <<<"$files")
  fi
  while IFS= read -r hook; do
    [ -n "$hook" ] || continue
    ! grep -qxF -- ".githooks/${hook##*/}" <<<"$files" || adopted=1
  done <<<"$templates"
  [ "$adopted" = 1 ] || return 0
  while IFS= read -r hook; do
    [ -z "$hook" ] || echo "templates/githooks/${hook##*/} .githooks/${hook##*/}"
  done <<<"$templates"
}

vendor_tree_of() { # <commit>
  local tree manifest
  tree=$(git rev-parse -q --verify "$1^{tree}") || return 2
  if manifest=$(git show "$1:VENDOR_PATHS" 2>/dev/null); then
    vendor_filter_tree "$tree" "$manifest"
  else
    echo "$tree"
  fi
}

vendoring_only() { # <rev> <paths>
  local rev=$1 record path base bases copy gd=''
  VENDORED_TREE=
  [ -n "$2" ] || return 1
  record=$(_vendor_record "$rev") || return 1
  if devkit_pinned "$rev"; then
    gd=$(devkit_pin_git_dir "${record%% *}") || return 1
    VENDORED_TREE=$(GIT_DIR=$gd vendor_tree_of "${record%% *}" 2>/dev/null) || return 1
  elif [ -z "$rev" ]; then
    VENDORED_TREE=$(git write-tree --prefix=devkit/ 2>/dev/null) || return 1
  else
    VENDORED_TREE=$(git rev-parse -q --verify "$rev:devkit") || return 1
  fi
  [ "$VENDORED_TREE" = "${record#* }" ] || return 1
  bases=$(base_copies "$rev") || return 1
  while IFS= read -r path; do
    case "$path" in ''|.devkit-rev) continue ;; devkit/*) [ -z "$gd" ] && continue; return 1 ;; esac
    base=$(awk -v c="$path" '$2 == c { print $1; exit }' <<<"$bases")
    [ -n "$base" ] || return 1
    copy=$(_vendor_entry "$rev" "$path")
    [ -n "$copy" ] || return 1
    if [ -n "$gd" ]; then
      [ "$copy" = "$(GIT_DIR=$gd _vendor_entry "${record%% *}" "$base")" ] || return 1
    else
      [ "$copy" = "$(_vendor_entry "$rev" "devkit/$base")" ] || return 1
    fi
  done <<<"$2"
}

vendored_from() { # <rev> <upstream> [<base rev>]
  local record commit base
  record=$(git show "$1:.devkit-rev" 2>/dev/null) || return 1
  commit=${record%% *}
  [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || return 1
  git merge-base --is-ancestor "$commit" "$2" 2>/dev/null || return 1
  [ "$(vendor_tree_of "$commit" 2>/dev/null)" = "${record#* }" ] || return 1
  [ -n "${3:-}" ] || return 0
  git cat-file -e "$3^{commit}" 2>/dev/null || return 1
  # A base with no .devkit-rev is a first vendoring: any upstream commit is forward of it. Only
  # an absent file counts as none; one git cannot read fails closed.
  base=$(git ls-tree "$3" -- .devkit-rev) || return 1
  [ -n "$base" ] || return 0
  base=$(git show "$3:.devkit-rev") || return 1
  git merge-base --is-ancestor "${base%% *}" "$commit" 2>/dev/null
}

devkit_sync_only() { # <rev> <base> <paths>
  local rev=$1 base=$2 vendored tmp status
  vendored=$(grep -vxF "$VENDOR_SYNC_BOUNDS" <<<"$3")
  vendoring_only "$rev" "$vendored" || return 1
  grep -qxF "$VENDOR_SYNC_BOUNDS" <<<"$3" || return 0
  [ -n "$base" ] && devkit_python || return 1
  tmp=$(mktemp -d "${TMPDIR:-/tmp}/sync-bounds.XXXXXX") || return 1
  # "$rev:" is the index when <rev> is "", as everywhere above.
  git show "$base:$VENDOR_SYNC_BOUNDS" >"$tmp/base.json" 2>/dev/null \
    && git show "$rev:$VENDOR_SYNC_BOUNDS" >"$tmp/head.json" 2>/dev/null \
    && "$DEVKIT_PYTHON" -I "$_VENDOR_PATHS_BIN/metrics_ratchet.py" tightens \
      --base-bounds "$tmp/base.json" --head-bounds "$tmp/head.json" >/dev/null
  status=$?
  rm -rf "$tmp"
  return "$status"
}
