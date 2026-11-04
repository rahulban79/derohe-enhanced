#!/bin/bash
# r25 (dero-rft §0.9 rule 5, B88): versioned private mirror of the Claude project memory, plus the scrubbed in-repo copy.
#
#   1. private copy: <dest>/<UTC stamp>/ (0700; files 0600), rsync -a WITHOUT --delete from the memory dir, with a
#      MANIFEST.sha256 (one '<sha256>  <file>' line per file) and <dest>/LATEST naming the newest stamp. A run whose
#      manifest equals the newest stamp's adds no stamp (no churn); a memory file that disappeared keeps its old copies.
#   2. scrubbed copy (with --repo): tools/memory-mirror/sync_mirror.py rebuilds <repo>/memory-mirror/ from the newest
#      private stamp through pubscrub.py, refuses any file that still carries a private identifier, and writes
#      memory-mirror/MANIFEST.sha256 ('<source sha256> <mirror sha256 or -> <file>').
#   3. drift check: harness/intel/tooling_intel.py (metric mirror_drift; 0 required at round end).
#
# The private copy lives OUTSIDE every repository and is never published; the in-repo copy is never published either
# (the GitHub sync excludes memory-mirror/). Nothing here prints file contents.
#
# usage: backup_memory.sh [--src DIR] [--dest DIR] [--repo DIR] [--pubscrub FILE] [--dry-run]
#   defaults: --src ~/.claude/projects/<project>/memory  --dest ~/derohe-persist/memory-mirror
#             --pubscrub: <repo>/harness/loop/TOOL_PATHS.json "pubscrub" ; no --repo = private copy only
set -u
PROJ=$(printf '%s' "$HOME/derohe-Release142" | tr '/' '-')
SRC="$HOME/.claude/projects/$PROJ/memory"
DEST="$HOME/derohe-persist/memory-mirror"
REPO=""
PUBSCRUB=""
DRY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --src) SRC="$2"; shift 2 ;;
    --dest) DEST="$2"; shift 2 ;;
    --repo) REPO="$2"; shift 2 ;;
    --pubscrub) PUBSCRUB="$2"; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "backup_memory: unknown argument $1" >&2; exit 2 ;;
  esac
done
[ -d "$SRC" ] || { echo "backup_memory: no memory dir" >&2; exit 3; }
manifest() { (cd "$1" && find . -maxdepth 1 -type f -name '*.md' | sed 's|^\./||' | LC_ALL=C sort | while read -r f; do
  printf '%s  %s\n' "$(shasum -a 256 "$f" | cut -d' ' -f1)" "$f"; done); }
NEW=$(manifest "$SRC")
LAST=""
[ -f "$DEST/LATEST" ] && LAST=$(cat "$DEST/LATEST")
if [ -n "$LAST" ] && [ -f "$DEST/$LAST/MANIFEST.sha256" ] && [ "$NEW" = "$(cat "$DEST/$LAST/MANIFEST.sha256")" ]; then
  echo "backup_memory: unchanged since $LAST ($(printf '%s\n' "$NEW" | grep -c .) files)"
  STAMP="$LAST"
else
  STAMP=$(date -u +%Y%m%dT%H%M%SZ)
  if [ "$DRY" = 1 ]; then echo "backup_memory: would write stamp $STAMP"; exit 0; fi
  umask 077
  mkdir -p "$DEST" && chmod 700 "$DEST"
  mkdir -p "$DEST/$STAMP"
  LINK=""
  [ -n "$LAST" ] && [ -d "$DEST/$LAST" ] && LINK="--link-dest=$DEST/$LAST"
  nice -n 15 rsync -a $LINK --include='*.md' --exclude='*' "$SRC/" "$DEST/$STAMP/"
  printf '%s\n' "$NEW" > "$DEST/$STAMP/MANIFEST.sha256"
  chmod 700 "$DEST/$STAMP"; chmod 600 "$DEST/$STAMP"/* 2>/dev/null
  # the copy must hash exactly as its source did (a file edited mid-copy fails here; re-run)
  if [ "$(manifest "$DEST/$STAMP")" != "$NEW" ]; then echo "backup_memory: copy does not match the source manifest" >&2; exit 4; fi
  printf '%s\n' "$STAMP" > "$DEST/LATEST"
  echo "backup_memory: wrote stamp $STAMP ($(printf '%s\n' "$NEW" | grep -c .) files)"
fi
if [ -n "$REPO" ]; then
  [ "$DRY" = 1 ] && { echo "backup_memory: would sync $REPO/memory-mirror from $STAMP"; exit 0; }
  nice -n 15 python3 -I "$(dirname "$0")/sync_mirror.py" --stamp "$DEST/$STAMP" --repo "$REPO" ${PUBSCRUB:+--pubscrub "$PUBSCRUB"} || exit $?
fi
