#!/bin/sh
# forensics/r26 replay (rft §0.8.3, gate G28): ONE command re-derives every derived/ file of dataset v2 from raw/ (and
# the pinned v1 RAW inputs) into a scratch dir and checks every SHA-256 against manifest.json and expected.sha256.
# Tier B blobs (tx bodies) are read from $FORENSICS_R26_STORE (default: $HOME/derohe-persist/forensics_raw_r26): v2 keeps
# its own store, since v1's replay hashes the listing of ITS store (replay.py store_index) and any added blob fails v1.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
store=${FORENSICS_R26_STORE:-$HOME/derohe-persist/forensics_raw_r26}
exec nice -n 15 python3 -I "$root/harness/forensics/v2.py" replay "$root/forensics/r26" --store "$store" "$@"
