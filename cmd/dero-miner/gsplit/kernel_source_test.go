package gsplit

import (
	"math/bits"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// r20 gpukernels: the split server's Metal source keeps the invariants its r20 speed-ups rely on. Bit-exactness itself
// is proved by the SelfTest every server start runs (and by TestRealGPUBitExact with GSPLIT_REAL=1); this test needs
// no GPU, so the routine pipeline and the mutation harness catch a source edit that silently breaks an invariant.

func readPOC(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("../../../gpu-miner-poc/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// registerOps is the Go statement of the server's rewrite rule (gpu_split_server.swift registerOps): a standard op
// line has exactly 4 statements, each assigning s[i] from s[i] and s[p2] only.
func registerOps(inc string) (out []string, kept []string) {
	const pre, suf = "  for(uint i=p1;i<p2;i++){ ", " } break; }"
	for _, l := range strings.Split(inc, "\n") {
		if strings.HasPrefix(l, pre) && strings.HasSuffix(l, suf) {
			var st []string
			for _, x := range strings.Split(l[len(pre):len(l)-len(suf)], ";") {
				if x = strings.TrimSpace(x); x != "" {
					st = append(st, x)
				}
			}
			ok := len(st) == 4
			for _, x := range st {
				c := strings.NewReplacer("s[i]", "x", "s[p2]", "y").Replace(x)
				if !strings.HasPrefix(x, "s[i]=") || strings.Contains(c, "s[") || strings.Contains(c, "hash") || strings.Contains(c, "(&") {
					ok = false
				}
			}
			if ok {
				out = append(out, l)
				continue
			}
			kept = append(kept, l)
		}
	}
	return
}

func TestSplitServerKernelInvariants(t *testing.T) {
	src := readPOC(t, "gpu_split_server.swift")
	inc := readPOC(t, "loop_ops.metal.inc")

	// 1. per-thread threadgroup state: s must start 8-aligned (the threadgroup u64le/fnv1a load whole words), and the
	//    encoder must reserve exactly that struct size per thread of the stage-1 threadgroup.
	m := regexp.MustCompile(`struct ST \{ uchar s\[256\]; RC4 r; uchar pad\[(\d+)\]; \};`).FindStringSubmatch(src)
	if m == nil {
		t.Fatal("struct ST not found")
	}
	pad, _ := strconv.Atoi(m[1])
	size := 256 + 256 + 2 + pad // s, RC4{s[256], i, j}, pad
	if size%8 != 0 {
		t.Fatalf("ST is %d bytes: per-thread s is not 8-aligned, the word loads of the threadgroup hashes would fault or misread", size)
	}
	if !strings.Contains(src, "*(threadgroup const ulong*)") {
		t.Fatal("threadgroup word loads gone: update this test with the kernel")
	}
	tm := regexp.MustCompile(`e\.setThreadgroupMemoryLength\((\d+)\*s1TGW, index: 0\)`).FindStringSubmatch(src)
	if tm == nil || tm[1] != strconv.Itoa(size) {
		t.Fatalf("threadgroup memory per thread %v != sizeof(ST) %d", tm, size)
	}
	if !strings.Contains(src, "threadsPerThreadgroup: MTLSize(width: min(n, op == 1 ? s1TGW : 32)") {
		t.Fatal("stage-1 dispatch width is not the width its threadgroup memory was sized for")
	}
	w := regexp.MustCompile(`var s1TGW = (\d+)\n`).FindStringSubmatch(src)
	if w == nil {
		t.Fatal("s1TGW default not found")
	}
	if v, _ := strconv.Atoi(w[1]); v < 1 || v > 32 || size*v%16 != 0 {
		t.Fatalf("s1TGW %d: threadgroup memory %d bytes must be a multiple of 16 and the width <= 32", v, size*v)
	}

	// 2. register-resident ops: 253 of the generated ops are rewritten (op 0 swaps s[p1]/s[p2] inside its loop and
	//    op 253 hashes per byte: those stay verbatim), the server refuses to start on any other count, and the
	//    rewritten table is the one compiled.
	conv, _ := registerOps(inc)
	if len(conv) != 253 {
		t.Fatalf("%d standard ops, want 253", len(conv))
	}
	for _, l := range conv {
		if strings.Contains(l, "s[p1]") || strings.Contains(l, "lhash") {
			t.Fatalf("rewritten op touches state outside s[i]/s[p2]: %s", l)
		}
	}
	for _, want := range []string{"if opsRegN != 253 {", `.replacingOccurrences(of: "%%OPS%%", with: opsReg)`} {
		if !strings.Contains(src, want) {
			t.Fatalf("server source lost %q", want)
		}
	}

	// 3. final SHA: the pipeline runs the unrolled k_shaw that is compiled into the library.
	for _, want := range []string{`pShaW = pso("k_shaw")`, "let msl = helpers + tgOverloads(helpers) + lutMSL + k1 + kShaU\n", "kernel void k_shaw(device const uint* SAB"} {
		if !strings.Contains(src, want) {
			t.Fatalf("server source lost %q", want)
		}
	}
	if !strings.Contains(src, "for i in 0..<64 {") || !strings.Contains(src, "let kShaU = shaCompressMSL() + ") {
		t.Fatal("unrolled SHA generator gone")
	}
}

// lutOps is the Go statement of the server's r22 table rule (gpu_split_server.swift lutOps): a standard op (the
// registerOps shape) is cut at its y-statements (x=x^y, x=x&y; any other use of y is refused) into at most 3 y-free
// segments. ops maps each table op to its segments and y-steps; special lists the ops that keep their verbatim case.
func lutOps(inc string) (ops map[int][2][]string, yops map[int][]string, special []int, refused []string) {
	const pre, suf = "  for(uint i=p1;i<p2;i++){ ", " } break; }"
	ops, yops = map[int][2][]string{}, map[int][]string{}
	lines := strings.Split(inc, "\n")
	label := regexp.MustCompile(`case (\d+):`)
	for k := 0; k < len(lines); k++ {
		l := lines[k]
		if !strings.HasPrefix(l, "case ") || !strings.HasSuffix(l, ": {") {
			continue
		}
		var nums []int
		for _, m := range label.FindAllStringSubmatch(l, -1) {
			v, _ := strconv.Atoi(m[1])
			nums = append(nums, v)
		}
		j := k + 1
		if j < len(lines) && lines[j] == "  rc4_ksa(&r, s);" {
			j++
		}
		body := ""
		if j < len(lines) {
			body = lines[j]
		}
		conv, std := registerOps(body)
		if len(conv) != 1 || len(std) != 0 {
			special = append(special, nums...)
			continue
		}
		var segs [][]string = [][]string{nil}
		var ys []string
		ok := true
		for _, x := range strings.Split(body[len(pre):len(body)-len(suf)], ";") {
			if x = strings.TrimSpace(x); x == "" {
				continue
			}
			c := strings.NewReplacer("s[i]", "x", "s[p2]", "y").Replace(x)
			switch {
			case c == "x=x^y" || c == "x=x&y":
				ys = append(ys, c)
				segs = append(segs, nil)
			case strings.Contains(c[2:], "y"):
				ok = false
			default:
				segs[len(segs)-1] = append(segs[len(segs)-1], c)
			}
		}
		if !ok || len(ys) > 2 {
			refused = append(refused, l)
			continue
		}
		for len(segs) < 3 {
			segs = append(segs, nil)
		}
		for _, o := range nums {
			ops[o] = [2][]string{{strings.Join(segs[0], ";"), strings.Join(segs[1], ";"), strings.Join(segs[2], ";")}, nil}
			yops[o] = ys
		}
	}
	return
}

// prim evaluates one y-free statement of loop_ops.metal.inc on a byte (the 14 forms the generator emits today).
func prim(t *testing.T, st string, x uint8) uint8 {
	rotl := func(v uint8, k uint) uint8 { return bits.RotateLeft8(v, int(k&7)) }
	switch strings.TrimPrefix(st, "x=") {
	case "uchar(uint(x)<<(uint(x)&3u))":
		return x << (x & 3)
	case "rotl8(x,1u)":
		return rotl(x, 1)
	case "uchar(uint(x)+uint(x))":
		return x + x
	case "x^uchar(popcount(uint(x)))":
		return x ^ uint8(bits.OnesCount8(x))
	case "rev8(x)":
		return bits.Reverse8(x)
	case "rotl8(x,uint(x))":
		return rotl(x, uint(x))
	case "rotl8(x,3u)":
		return rotl(x, 3)
	case "uchar(0xffu^uint(x))":
		return ^x
	case "uchar(uint(x)>>(uint(x)&3u))":
		return x >> (x & 3)
	case "uchar(uint(x)-(uint(x)^97u))":
		return x - (x ^ 97)
	case "rotl8(x,5u)":
		return rotl(x, 5)
	case "x^rotl8(x,4u)":
		return x ^ rotl(x, 4)
	case "x^rotl8(x,2u)":
		return x ^ rotl(x, 2)
	case "uchar(uint(x)*uint(x))":
		return x * x
	}
	t.Fatalf("unknown statement %q: extend prim with the new form", st)
	return 0
}

// r22 gpukernels: the table-driven stage-1 ops. A GPU-free proof of the decomposition the server relies on: for every
// table op, every byte x and every y, the 3 tables and the y-masks give the same byte as the op's 4 statements applied
// in order. The GPU builds the tables from the same generated statements (k_lut), the server refuses any other shape,
// and k_s1tg binds and reads them; bit-exactness on the GPU itself is proved by the SelfTest and TestRealGPUBitExact.
func TestSplitServerLUTOps(t *testing.T) {
	src := readPOC(t, "gpu_split_server.swift")
	inc := readPOC(t, "loop_ops.metal.inc")
	ops, yops, special, refused := lutOps(inc)
	if len(refused) != 0 || len(special) != 2 || special[0] != 0 || special[1] != 253 {
		t.Fatalf("special ops %v (want [0 253]), refused %v", special, refused)
	}
	if len(ops) != 254 { // 252 single-label cases + "case 254: case 255:"
		t.Fatalf("%d table ops, want 254", len(ops))
	}
	seg := func(s string, x uint8) uint8 {
		if s == "" {
			return x
		}
		for _, st := range strings.Split(s, ";") {
			x = prim(t, st, x)
		}
		return x
	}
	for o, sg := range ops {
		var T [3][256]uint8
		for q := 0; q < 3; q++ {
			for x := 0; x < 256; x++ {
				T[q][x] = seg(sg[0][q], uint8(x))
			}
		}
		// the full statement list in order (segments with the y-steps between them)
		var all []string
		for q := 0; q < 3; q++ {
			if sg[0][q] != "" {
				all = append(all, strings.Split(sg[0][q], ";")...)
			}
			if q < len(yops[o]) {
				all = append(all, yops[o][q])
			}
		}
		if len(all) != 4 {
			t.Fatalf("op %d: %d statements, want 4", o, len(all))
		}
		for y := 0; y < 256; y++ {
			am, xm := [2]uint8{0xff, 0xff}, [2]uint8{0, 0}
			for q, yo := range yops[o] {
				if yo == "x=x^y" {
					xm[q] = uint8(y)
				} else {
					am[q] = uint8(y)
				}
			}
			for x := 0; x < 256; x++ {
				v := uint8(x)
				for _, st := range all {
					switch st {
					case "x=x^y":
						v ^= uint8(y)
					case "x=x&y":
						v &= uint8(y)
					default:
						v = prim(t, st, v)
					}
				}
				if got := T[2][(T[1][(T[0][x]&am[0])^xm[0]]&am[1])^xm[1]]; got != v {
					t.Fatalf("op %d x=%d y=%d: tables give %d, statements %d", o, x, y, got, v)
				}
			}
		}
	}
	for _, want := range []string{
		"if lutN != 253 || lutOPD.contains(0xFFFFFFFF) || lutOPD.enumerated().filter({ $0.element == 0x10000 }).map({ $0.offset }) != [0, 253] {",
		"device const uchar* LUT [[buffer(5)]], uint gid [[thread_position_in_grid]], uint lid [[thread_position_in_threadgroup]], threadgroup ST* tg",
		"stage1Body.replacingOccurrences(of: opSwitch, with: lutStep).replacingOccurrences(of: \"%%WRITE%%\"",
		"if !stage1Body.contains(opSwitch) {",
		"e.setBuffer(lutBuf, offset: 0, index: 5) // r22 op tables",
		`let p = pso("k_lut")`,
		"uchar x=T0[(v>>(8u*q))&0xffu]; x=(x&am1)^xm1; x=T0[256u+x]; x=(x&am2)^xm2; rr|=uint(T0[512u+x])<<(8u*q);",
		"uint lo=(w<p1)?(p1-w):0u; uint hi=min(4u,p2-w); uint m=(hi>=4u?0xffffffffu:((1u<<(8u*hi))-1u)) & ~((1u<<(8u*lo))-1u);",
		"for(uint w=p1&~3u;w<p2;w+=4){",
		"*(threadgroup uint*)(s+w)=(v&~m)|(rr&m);",
		"uchar am1=(dd&2u)?y:uchar(0xff), xm1=(dd&1u)?y:uchar(0), am2=(dd&8u)?y:uchar(0xff), xm2=(dd&4u)?y:uchar(0);",
		`if c == "x=x^y" { yops.append(1); segs.append([]) }`,
		`else if c == "x=x&y" { yops.append(2); segs.append([]) }`,
		"if(dd & 0x20000u) rc4_ksa(&r, s);",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("server source lost %q", want)
		}
	}
}

// r22 gpukernels: the word form of the table loop touches exactly the bytes [p1,p2): for every p1 <= p2 <= 255 the
// Go port of its mask (lo/hi/m, the server's MSL line) changes those bytes and writes every other byte of each word back
// unchanged, as the byte loop does.
func TestSplitServerWordMask(t *testing.T) {
	for p1 := uint32(0); p1 < 256; p1++ {
		for p2 := p1; p2 < 256; p2++ {
			var s [256]byte
			for i := range s {
				s[i] = byte(i*7 + 1)
			}
			want := s
			for i := p1; i < p2; i++ {
				want[i] = ^want[i] // stands for the table op
			}
			for w := p1 &^ 3; w < p2; w += 4 {
				v := uint32(s[w]) | uint32(s[w+1])<<8 | uint32(s[w+2])<<16 | uint32(s[w+3])<<24
				rr := ^v
				lo := uint32(0)
				if w < p1 {
					lo = p1 - w
				}
				hi := p2 - w
				if hi > 4 {
					hi = 4
				}
				m := uint32(0xffffffff)
				if hi < 4 {
					m = (1 << (8 * hi)) - 1
				}
				m &^= (1 << (8 * lo)) - 1
				v = (v &^ m) | (rr & m)
				s[w], s[w+1], s[w+2], s[w+3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
			}
			if s != want {
				t.Fatalf("p1=%d p2=%d: word loop changed the wrong bytes", p1, p2)
			}
		}
	}
	src := readPOC(t, "gpu_split_server.swift")
	if !strings.Contains(src, "uint lo=(w<p1)?(p1-w):0u; uint hi=min(4u,p2-w); uint m=(hi>=4u?0xffffffffu:((1u<<(8u*hi))-1u)) & ~((1u<<(8u*lo))-1u);") {
		t.Fatal("server word mask is not the one this test models")
	}
}

// prgaRef is the reference RC4 PRGA of the kernels (helpers rc4_prga): buf ^= keystream.
func prgaRef(S *[256]byte, i, j *byte, buf []byte) {
	for k := range buf {
		*i++
		x := S[*i]
		*j += x
		y := S[*j]
		S[*i], S[*j] = y, x
		buf[k] ^= S[byte(x+y)]
	}
}

// prgaAhead is the Go port of the r22 threadgroup PRGA (gpu_split_server.swift tgOverloads): S[i+1] and S[x+y] are
// read before the swap stores and fixed up for them, and the keystream is xored a word at a time.
func prgaAhead(S *[256]byte, pi, pj *byte, buf []byte) {
	i, j := uint32(*pi), uint32(*pj)
	x := uint32(S[(i+1)&255])
	for k := 0; k < len(buf); k += 4 {
		w := uint32(0)
		for q := uint32(0); q < 4; q++ {
			i = (i + 1) & 255
			j = (j + x) & 255
			y := uint32(S[j])
			i1 := (i + 1) & 255
			xn := uint32(S[i1])
			tt := (x + y) & 255
			o := uint32(S[tt])
			S[i], S[j] = byte(y), byte(x)
			if tt == j {
				o = x
			} else if tt == i {
				o = y
			}
			if i1 == j {
				xn = x
			}
			w |= o << (8 * q)
			x = xn
		}
		buf[k] ^= byte(w)
		buf[k+1] ^= byte(w >> 8)
		buf[k+2] ^= byte(w >> 16)
		buf[k+3] ^= byte(w >> 24)
	}
	*pi, *pj = byte(i), byte(j)
}

// r22 gpukernels: the load-ahead PRGA gives the reference keystream and leaves the reference state, call after call
// (the kernels always call it with n=256 on an 8-aligned buffer). The i==j, t==i, t==j and i+1==j fix-ups are all hit.
func TestSplitServerPRGALoadAhead(t *testing.T) {
	var SA, SB [256]byte
	for i := range SA {
		SA[i] = byte(i)
	}
	key := []byte("r22 gpukernels load-ahead PRGA key")
	var jj byte
	for i := 0; i < 256; i++ { // KSA
		jj += SA[i] + key[i%len(key)]
		SA[i], SA[jj] = SA[jj], SA[i]
	}
	SB = SA
	var ia, ja, ib, jb byte
	hits := [3]int{}
	for call := 0; call < 4000; call++ {
		bufA := make([]byte, 256)
		for k := range bufA {
			bufA[k] = byte(k*31 + call)
		}
		bufB := append([]byte(nil), bufA...)
		// count the fix-up cases this call exercises (on a copy, before the reference advances)
		{
			S, i, j := SA, ia, ja
			for k := 0; k < 256; k++ {
				i++
				x := S[i]
				j += x
				y := S[j]
				if i+1 == j {
					hits[0]++
				}
				if t := x + y; t == j {
					hits[1]++
				} else if t == i {
					hits[2]++
				}
				S[i], S[j] = y, x
			}
		}
		prgaRef(&SA, &ia, &ja, bufA)
		prgaAhead(&SB, &ib, &jb, bufB)
		if string(bufA) != string(bufB) || SA != SB || ia != ib || ja != jb {
			t.Fatalf("call %d: load-ahead PRGA differs from the reference", call)
		}
	}
	if hits[0] == 0 || hits[1] == 0 || hits[2] == 0 {
		t.Fatalf("fix-up cases not exercised: %v", hits)
	}
	src := readPOC(t, "gpu_split_server.swift")
	for _, want := range []string{
		"uint y=S[j]; uint i1=(i+1)&255u; uint xn=S[i1]; uint tt=(x+y)&255u; uint o=S[tt];",
		"S[i]=uchar(y); S[j]=uchar(x); o=(tt==j)?x:((tt==i)?y:o); xn=(i1==j)?x:xn; w|=o<<(8u*q); x=xn; }",
		" *(threadgroup uint*)(buf+k)^=w; } r->i=uchar(i); r->j=uchar(j); }",
		`if l.hasPrefix("static void rc4_prga(") {`,
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("server PRGA lost %q (this test models that line)", want)
		}
	}
}
