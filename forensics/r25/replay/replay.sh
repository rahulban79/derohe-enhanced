#!/bin/sh
# forensics/r25 replay (rft §0.8.3, gate G28): ONE command re-derives every derived/ file from raw/ with the pinned
# tools bound by content pins (manifest content_pins, harness/forensics/pins.py: any commit with identical pinned bytes), into
# a scratch dir, and checks every SHA-256 against manifest.json and expected.sha256.
# Tier B blobs are read from $FORENSICS_STORE (default: $HOME/derohe-persist/forensics_raw) when present; the
# archive_state files are re-derived only with --archive-copy DIR (an APFS clone of our replaywall archive), else
# hash-checked (mode partial). Extra arguments pass through, e.g. --record harness/runtime/forensics_replay.json.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
store=${FORENSICS_STORE:-$HOME/derohe-persist/forensics_raw}
if [ -d "$store/blobs" ]; then set -- --store "$store" "$@"; fi
exec nice -n 15 python3 -I "$root/harness/forensics/replay.py" "$root/forensics/r25" "$@"
