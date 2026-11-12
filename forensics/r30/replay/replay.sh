#!/bin/sh
# forensics/r30 replay (rft §0.8.3, gate G28): ONE command checks the content pins (tools + decoder inputs), re-derives
# every derived/ file of dataset v5 from raw/ (v4.derive, then the v5 files) into a scratch dir and checks every
# SHA-256. Tier B blobs from $FORENSICS_R28_STORE, the S0 checkpoint from $FORENSICS_R29_DEEP (both read-only).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
store=${FORENSICS_R28_STORE:-$HOME/derohe-persist/forensics_raw_r26}
exec nice -n 15 python3 -I "$root/harness/forensics/v5.py" replay "$root/forensics/r30" --store "$store" "$@"
