#!/bin/bash
# Build the GPU servers from source and record the build in BUILD_STAMPS (Round 21, storageops).
#
#   gpu-miner-poc/build.sh                      # the two the miner runs: gpu_hash_sais gpu_split_server
#   gpu-miner-poc/build.sh gpu_split_server     # one
#   gpu-miner-poc/build.sh --check              # verify every stamp, build nothing (exit 1 on drift)
#
# The binaries are tracked in git because `dero-miner --gpu=gpu-miner-poc/gpu_hash_sais` runs them from the checkout.
# A text patch cannot carry a rebuilt binary, and swiftc output is not reproducible (LC_UUID and the signature change
# per build), so the stamp records the SHA-256 of the source and of the binary THIS build produced; dero-miner warns
# at GPU start (and exports dero_miner_gpu_binary_stale) when either no longer matches.
# The new binary is renamed over the old one, so a running server keeps its inode; restart the miner to use it.
set -euo pipefail
cd "$(dirname "$0")"
STAMPS=BUILD_STAMPS
sum() { shasum -a 256 "$1" | cut -d' ' -f1; }

if [ "${1:-}" = "--check" ]; then
	rc=0
	while read -r name src bin; do
		case "$name" in ''|'#'*) continue ;; esac
		[ "$(sum "$name.swift")" = "$src" ] || { echo "DRIFT $name.swift changed after the recorded build"; rc=1; }
		[ "$(sum "$name")" = "$bin" ] || { echo "DRIFT $name is not the recorded build"; rc=1; }
	done < "$STAMPS"
	[ $rc = 0 ] && echo "all stamps match"
	exit $rc
fi

targets=("$@")
[ ${#targets[@]} -gt 0 ] || targets=(gpu_hash_sais gpu_split_server)
for name in "${targets[@]}"; do
	[ -f "$name.swift" ] || { echo "no $name.swift" >&2; exit 1; }
	tmp="$name.new.$$"
	xcrun swiftc -O "$name.swift" -o "$tmp"
	mv -f "$tmp" "$name"
	line="$name $(sum "$name.swift") $(sum "$name")"
	{ grep -v "^$name " "$STAMPS" 2>/dev/null || true; echo "$line"; } > "$STAMPS.tmp.$$"
	mv -f "$STAMPS.tmp.$$" "$STAMPS"
	echo "built $line"
done
