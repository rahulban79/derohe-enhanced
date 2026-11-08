#!/bin/sh
# forensics/r28d replay (rft §0.8.3, gate G28): ONE command checks the content pins (tools + decoder inputs), re-derives
# every derived/ file of dataset v4 from raw/ (v3.derive, then the two v4 files) into a scratch dir and checks every
# SHA-256. Tier B blobs (tx bodies) are read from $FORENSICS_R28_STORE (default: v2's store, shared, never written).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
store=${FORENSICS_R28_STORE:-$HOME/derohe-persist/forensics_raw_r26}
exec nice -n 15 python3 -I "$root/harness/forensics/v4.py" replay "$root/forensics/r28d" --store "$store" "$@"
