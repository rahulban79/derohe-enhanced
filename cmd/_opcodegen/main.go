package main

// Stage-3b codegen: read astrobwt/astrobwtv3/pow.go, extract the 256-opcode switch,
// and emit the equivalent MSL switch. The op vocabulary is the 16 frozen lines from
// random_code_gen.go; any op-line that doesn't match one of them is a hard error (so
// we never silently mistranslate). Output: gpu-miner-poc/loop_ops.metal.inc
import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// normalized-Go (spaces removed, comment stripped) -> MSL statement operating on s[i], p2=pos2
var opMap = map[string]string{
	"step_3[i]+=step_3[i]":                                  "s[i]=uchar(uint(s[i])+uint(s[i]));",
	"step_3[i]-=(step_3[i]^97)":                             "s[i]=uchar(uint(s[i])-(uint(s[i])^97u));",
	"step_3[i]*=step_3[i]":                                  "s[i]=uchar(uint(s[i])*uint(s[i]));",
	"step_3[i]=step_3[i]^step_3[pos2]":                      "s[i]=s[i]^s[p2];",
	"step_3[i]=^step_3[i]":                                  "s[i]=uchar(0xffu^uint(s[i]));",
	"step_3[i]=step_3[i]&step_3[pos2]":                      "s[i]=s[i]&s[p2];",
	"step_3[i]=step_3[i]<<(step_3[i]&3)":                    "s[i]=uchar(uint(s[i])<<(uint(s[i])&3u));",
	"step_3[i]=step_3[i]>>(step_3[i]&3)":                    "s[i]=uchar(uint(s[i])>>(uint(s[i])&3u));",
	"step_3[i]=bits.Reverse8(step_3[i])":                    "s[i]=rev8(s[i]);",
	"step_3[i]=step_3[i]^byte(bits.OnesCount8(step_3[i]))":  "s[i]=s[i]^uchar(popcount(uint(s[i])));",
	"step_3[i]=bits.RotateLeft8(step_3[i],int(step_3[i]))":  "s[i]=rotl8(s[i],uint(s[i]));",
	"step_3[i]=bits.RotateLeft8(step_3[i],1)":               "s[i]=rotl8(s[i],1u);",
	"step_3[i]=step_3[i]^bits.RotateLeft8(step_3[i],2)":     "s[i]=s[i]^rotl8(s[i],2u);",
	"step_3[i]=bits.RotateLeft8(step_3[i],3)":               "s[i]=rotl8(s[i],3u);",
	"step_3[i]=step_3[i]^bits.RotateLeft8(step_3[i],4)":     "s[i]=s[i]^rotl8(s[i],4u);",
	"step_3[i]=bits.RotateLeft8(step_3[i],5)":               "s[i]=rotl8(s[i],5u);",
}

func norm(line string) string {
	if i := strings.Index(line, "//"); i >= 0 {
		line = line[:i]
	}
	line = strings.ReplaceAll(line, " ", "")
	line = strings.ReplaceAll(line, "\t", "")
	return strings.TrimSpace(line)
}

func main() {
	src, err := os.ReadFile("astrobwt/astrobwtv3/pow.go")
	if err != nil {
		panic(err)
	}
	lines := strings.Split(string(src), "\n")

	// find the switch region: from "switch op {" to the matching default/close before the post-switch hashes
	start, end := -1, -1
	for i, l := range lines {
		if strings.Contains(l, "switch op {") {
			start = i
		}
		if start >= 0 && strings.Contains(l, "if step_3[pos1]-step_3[pos2] < 0x10") {
			end = i
			break
		}
	}
	if start < 0 || end < 0 {
		panic("switch region not found")
	}
	caseRe := regexp.MustCompile(`^\s*case\s+([0-9,\s]+):`)

	type Case struct {
		nums  string
		ops   []string
		extra []string // extra statements INSIDE the for-loop, after the 4 ops (case 0 reverse, case 253 hash)
		rc4   bool     // case 254,255's NewCipher reset (BEFORE the for-loop)
	}
	var cases []Case
	var cur *Case
	inRandom := false
	for i := start; i < end; i++ {
		l := lines[i]
		if m := caseRe.FindStringSubmatch(l); m != nil {
			cases = append(cases, Case{nums: strings.ReplaceAll(strings.TrimSpace(m[1]), " ", "")})
			cur = &cases[len(cases)-1]
			inRandom = false
			continue
		}
		if cur == nil {
			continue
		}
		if strings.Contains(l, "INSERT_RANDOM_CODE_START") {
			inRandom = true
			continue
		}
		if strings.Contains(l, "INSERT_RANDOM_CODE_END") {
			inRandom = false
			continue
		}
		if inRandom {
			n := norm(l)
			if n == "" {
				continue
			}
			msl, ok := opMap[n]
			if !ok {
				fmt.Fprintf(os.Stderr, "UNKNOWN OP (case %s) line %d: %q  normalized=%q\n", cur.nums, i+1, l, n)
				os.Exit(1)
			}
			cur.ops = append(cur.ops, msl)
			continue
		}
		// extra statements inside the for-loop (after the 4 ops) — must be translated too
		if strings.Contains(l, "bits.Reverse8(step_3[pos1])") {
			cur.extra = append(cur.extra, "uchar ra=rev8(s[p1]), rb=rev8(s[p2]); s[p2]=ra; s[p1]=rb;")
		}
		if strings.Contains(l, "prev_lhash = lhash + prev_lhash") {
			cur.extra = append(cur.extra, "prev_lhash=lhash+prev_lhash;")
		}
		if strings.Contains(l, "lhash = xxhash.Sum64(step_3[:pos2])") {
			cur.extra = append(cur.extra, "lhash=xxh64(s,p2);")
		}
		if strings.Contains(l, "rc4s = NewCipher(step_3[:])") {
			cur.rc4 = true
		}
	}

	// emit MSL
	var b strings.Builder
	b.WriteString("// AUTO-GENERATED from pow.go by cmd/_opcodegen — do not edit.\n")
	total := 0
	for _, c := range cases {
		if len(c.ops) != 4 {
			fmt.Fprintf(os.Stderr, "case %s has %d ops (expected 4)\n", c.nums, len(c.ops))
			os.Exit(1)
		}
		labels := ""
		for _, n := range strings.Split(c.nums, ",") {
			labels += "case " + n + ": "
			total++
		}
		b.WriteString(labels + "{\n")
		if c.rc4 {
			b.WriteString("  rc4_ksa(&r, s);\n") // rc4s = NewCipher(step_3) -> re-run KSA on current s
		}
		b.WriteString("  for(uint i=p1;i<p2;i++){ ")
		for _, op := range c.ops {
			b.WriteString(op + " ")
		}
		for _, ex := range c.extra {
			b.WriteString(ex + " ")
		}
		b.WriteString("} break; }\n")
	}
	if err := os.WriteFile("gpu-miner-poc/loop_ops.metal.inc", []byte(b.String()), 0644); err != nil {
		panic(err)
	}
	fmt.Printf("emitted %d cases covering %d opcodes -> gpu-miner-poc/loop_ops.metal.inc\n", len(cases), total)
}
