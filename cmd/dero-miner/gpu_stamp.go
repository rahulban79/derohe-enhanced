package main

// Round 21 (storageops): source/binary drift detection for the tracked GPU servers.
//
// --gpu=gpu-miner-poc/gpu_hash_sais (and gpu_split_server next to it) run compiled Swift binaries that are TRACKED in
// git, because the user's run command points into the checkout. A round that changes a .swift file ships a text
// patch, which cannot carry the rebuilt binary (r20: "the tracked binary gpu-miner-poc/gpu_split_server is still the
// r19 build (a text patch cannot carry it)"); the only guard was a human remembering to rebuild and read the banner.
// swiftc output is not reproducible (two builds of the same source differ in LC_UUID and the code signature), so a
// rebuild cannot prove provenance after the fact. gpu-miner-poc/build.sh therefore records, at build time, the
// SHA-256 of the source and of the binary it produced in gpu-miner-poc/BUILD_STAMPS. The miner checks the binary it
// is about to start against that record and says, loudly, when the .swift changed after the build or the binary is
// not the recorded build. It only warns: a stale binary still passes (or fails) the bit-exact self-test as before.

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
)

const GPU_STAMP_FILE = "BUILD_STAMPS"

type gpu_stamp struct{ src, bin string } // hex SHA-256

// parse_gpu_stamps reads "name src_sha256 bin_sha256" lines; '#' starts a comment.
func parse_gpu_stamps(rd io.Reader) map[string]gpu_stamp {
	m := map[string]gpu_stamp{}
	sc := bufio.NewScanner(rd)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) == 3 && is_sha256_hex(f[1]) && is_sha256_hex(f[2]) {
			m[f[0]] = gpu_stamp{strings.ToLower(f[1]), strings.ToLower(f[2])}
		}
	}
	return m
}

// is_sha256_hex: 64 hex digits. r22 (FuzzMinerParsers): a 64-byte field with non-hex bytes was accepted, and
// strings.ToLower turned invalid UTF-8 into U+FFFD, so the stored "digest" was not even 64 characters.
func is_sha256_hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func sha256_file(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// gpu_stamp_check compares bin and bin+".swift" with BUILD_STAMPS in bin's directory. stale is true only for a
// proven mismatch; a missing stamp file, entry or source is reported but is not "stale" (a hand-built binary
// elsewhere is legitimate).
func gpu_stamp_check(bin string) (status string, stale bool) {
	dir, name := filepath.Dir(bin), filepath.Base(bin)
	f, err := os.Open(filepath.Join(dir, GPU_STAMP_FILE))
	if err != nil {
		return "no " + GPU_STAMP_FILE + " next to the binary (unstamped build)", false
	}
	stamps := parse_gpu_stamps(f)
	f.Close()
	st, ok := stamps[name]
	if !ok {
		return "no stamp entry for " + name, false
	}
	binsum, err := sha256_file(bin)
	if err != nil {
		return "binary unreadable: " + err.Error(), false
	}
	srcsum, serr := sha256_file(filepath.Join(dir, name+".swift"))
	switch {
	case serr == nil && srcsum != st.src:
		return name + ".swift changed after the recorded build: rebuild with gpu-miner-poc/build.sh " + name, true
	case binsum != st.bin:
		return name + " is not the recorded build of its source (a text patch cannot carry binaries): rebuild with gpu-miner-poc/build.sh " + name, true
	case serr != nil:
		return "binary matches its stamp; source not found", false
	}
	return "ok (binary is the recorded build of " + name + ".swift)", false
}

var gpu_binaries_stale int32 // exported as dero_miner_gpu_binary_stale

// check_gpu_binary logs the stamp status of a GPU server binary before it is started and counts a stale one.
func check_gpu_binary(bin string) {
	status, stale := gpu_stamp_check(bin)
	if stale {
		atomic.AddInt32(&gpu_binaries_stale, 1)
		logger.Error(nil, "GPU server binary is STALE", "bin", bin, "status", status)
		return
	}
	logger.Info("GPU server binary", "bin", bin, "stamp", status)
}
