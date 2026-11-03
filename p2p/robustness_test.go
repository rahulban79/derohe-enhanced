package p2p

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/deroproject/derohe/globals"
)

// Verify_Handshake must refuse, never panic, on any peer-supplied version string, and keep accepting what it
// accepted before.
func TestVerifyHandshakeNeverPanics(t *testing.T) {
	saved := globals.Config.Network_ID
	defer func() { globals.Config.Network_ID = saved }()
	for _, c := range []struct {
		v    string
		want bool
	}{
		{"3.6.0-153.DEROHE.STARGATE+22102026", true}, // this build
		{"3.5.2-115.DEROHE.STARGATE+26022022", true},
		{"3.4.141-88.DEROHE.STARGATE+22112021", true}, // the oldest pre-release still admitted (pre >= 88)
		{"3.4.141-87.DEROHE.STARGATE+22112021", false},
		{"3.4.0", false},         // no pre-release tag: upstream indexed v.Pre[0] and panicked
		{"not-a-version", false}, // upstream MustParse panicked
		{"", false},
		{string(make([]byte, 200)), false},
	} {
		h := Handshake_Struct{DaemonVersion: c.v}
		h.Network_ID = globals.Config.Network_ID
		got := func() (ok bool) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%q panicked: %v", c.v, r)
				}
			}()
			return Verify_Handshake(&h)
		}()
		if got != c.want {
			t.Errorf("%q: got %v want %v", c.v, got, c.want)
		}
	}
}

func TestAvgOffsetAllZeroDoesNotPanic(t *testing.T) {
	c := &Connection{}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("calculate_avg_offset panicked on all-zero samples: %v", r)
		}
	}()
	c.calculate_avg_offset()
	if c.clock_offset.Load() != 0 {
		t.Fatalf("clock_offset = %d, want 0", c.clock_offset.Load())
	}
	c.clock_offsets[3] = 4000
	c.clock_offsets[5] = 2000
	c.calculate_avg_offset()
	if c.clock_offset.Load() != 3000 {
		t.Fatalf("clock_offset = %d, want the mean of the non-zero samples (3000)", c.clock_offset.Load())
	}
}

func TestWriteJSONAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "peers.json")
	if err := os.WriteFile(p, []byte(`{"old":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := write_json_atomic(p, map[string]int{"new": 2}); err != nil {
		t.Fatal(err)
	}
	var got map[string]int
	b, _ := os.ReadFile(p)
	if err := json.Unmarshal(b, &got); err != nil || got["new"] != 2 || len(got) != 1 {
		t.Fatalf("file holds %s (err %v)", b, err)
	}
	left, _ := filepath.Glob(filepath.Join(dir, "*.tmp-*"))
	if len(left) != 0 {
		t.Fatalf("temporary files left behind: %v", left)
	}
}

// The 2026-10-22 defect: connected peers were saved with an hours-old LastConnected and purged on reload.
func TestStampConnectedRefreshesOnlyConnectedPeers(t *testing.T) {
	peers := map[string]*Peer{
		"1.2.3.4": {Address: "1.2.3.4:11011", LastConnected: 100},
		"5.6.7.8": {Address: "5.6.7.8:11011", LastConnected: 100},
	}
	n := stamp_connected(peers, 9999, func(a string) bool { return a == "1.2.3.4:11011" })
	if n != 1 || peers["1.2.3.4"].LastConnected != 9999 || peers["5.6.7.8"].LastConnected != 100 {
		t.Fatalf("n=%d stamps %d/%d", n, peers["1.2.3.4"].LastConnected, peers["5.6.7.8"].LastConnected)
	}
}

// discovery p2p-security-04: a length prefix is a claim; memory must follow the bytes that arrive, and a frame cut short
// must fail with the error text log_call_failure classifies.
func TestReadDataFrameGrowsWithData(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	go func() {
		Write_Data_Frame(b, map[string]int{"x": 1})
		b.Close()
	}()
	var got map[string]int
	if err := Read_Data_Frame(a, &got); err != nil || got["x"] != 1 {
		t.Fatalf("round trip: %v %v", got, err)
	}

	c, d := net.Pipe()
	defer c.Close()
	go func() {
		var prefix [4]byte
		binary.LittleEndian.PutUint32(prefix[:], 40<<20) // claims 40 MB
		d.Write(prefix[:])
		d.Write([]byte{1, 2, 3}) // sends 3 bytes
		d.Close()
	}()
	var ms runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms)
	before := ms.TotalAlloc
	err := Read_Data_Frame(c, &got)
	runtime.ReadMemStats(&ms)
	if err == nil || !strings.Contains(err.Error(), "Could not read data size") {
		t.Fatalf("short frame: err = %v", err)
	}
	if grew := ms.TotalAlloc - before; grew > 4<<20 {
		t.Fatalf("a 40 MB claim with 3 bytes sent allocated %d bytes", grew)
	}
}
