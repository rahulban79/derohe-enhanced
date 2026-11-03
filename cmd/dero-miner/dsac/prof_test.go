//go:build darwin && arm64 && cgo

package dsac

// Round 22: descriptor.c's DSA_PROF phase timer must work on this platform. It used to include <intrin.h> and call
// __rdtsc (x86/MSVC only), so it did not build on arm64 at all; the arm64 reader added in r22 must actually read the
// counter (the first draft wrote "isb; mrs" and Apple's assembler took ';' as a comment, so it returned a stale
// register and every phase came out as garbage). This compiles descriptor.c with -DDSA_PROF into a tiny C program,
// sorts real stage-1 texts, and checks the mechanism: every phase is non-zero and their sum is bounded by the wall time
// mach_absolute_time (the same 24 MHz counter, read by libc, not by our asm) saw around the sorts.

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const profMain = `
#include <stdio.h>
#include <stdlib.h>
#include <mach/mach_time.h>
#include DSA_SRC
int main(int argc, char** argv) {
    FILE* f = fopen(argv[1], "rb");
    if (!f) return 2;
    static uint8_t buf[1 << 22];
    size_t L = fread(buf, 1, sizeof buf, f);
    fclose(f);
    int32_t* sa = malloc(sizeof(int32_t) * 256 * 384);
    unsigned long long w0 = mach_absolute_time();
    int fails = 0, texts = 0;
    for (size_t o = 0; o + 4 <= L;) {
        uint32_t n;
        memcpy(&n, buf + o, 4);
        o += 4;
        if (dsa_descriptor_suffix_array(buf + o, sa, (int32_t)n)) fails++;
        o += n;
        texts++;
    }
    unsigned long long w1 = mach_absolute_time();
    printf("%d %d %llu %llu %llu %llu %llu %llu\n", texts, fails, w1 - w0,
           dsa_prof[0], dsa_prof[1], dsa_prof[2], dsa_prof[3], dsa_prof[4]);
    return 0;
}
`

func TestProfTimerArm64(t *testing.T) {
	cc, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("clang not on PATH")
	}
	src, err := filepath.Abs("descriptor.c")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var buf bytes.Buffer
	for _, txt := range stage1Texts(t)[:32] {
		binary.Write(&buf, binary.LittleEndian, uint32(len(txt)))
		buf.Write(txt)
	}
	corpus := filepath.Join(dir, "corpus.bin")
	if err := os.WriteFile(corpus, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	mainC := filepath.Join(dir, "prof_main.c")
	if err := os.WriteFile(mainC, []byte(profMain), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "prof")
	cmd := exec.Command(cc, "-O2", "-mcpu=apple-m1", "-Wno-c23-extensions", "-DDSA_PROF", `-DDSA_SRC="`+src+`"`, "-I", filepath.Dir(src), mainC, "-o", bin)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("DSA_PROF build failed: %v\n%s", err, out)
	}
	out, err := exec.Command(bin, corpus).Output()
	if err != nil {
		t.Fatalf("DSA_PROF run failed: %v", err)
	}
	f := strings.Fields(string(out))
	if len(f) != 8 {
		t.Fatalf("unexpected output %q", out)
	}
	v := make([]uint64, len(f))
	for i := range f {
		if v[i], err = strconv.ParseUint(f[i], 10, 64); err != nil {
			t.Fatal(err)
		}
	}
	texts, fails, wall := v[0], v[1], v[2]
	if texts != 32 || fails != 0 {
		t.Fatalf("sorted %d texts, %d declined", texts, fails)
	}
	var sum uint64
	for i, name := range []string{"runs", "walk", "radix", "merge"} {
		if v[3+i] == 0 || v[3+i] > wall {
			t.Fatalf("phase %s = %d ticks, wall %d: the counter is not being read", name, v[3+i], wall)
		}
	}
	for _, p := range v[3:] {
		sum += p
	}
	if sum > wall+wall/20 {
		t.Fatalf("phases sum to %d ticks but the sorts took %d: the counter is not being read", sum, wall)
	}
	t.Logf("32 texts: wall %d ticks, phases runs %d walk %d radix %d merge %d tail %d", wall, v[3], v[4], v[5], v[6], v[7])
}
