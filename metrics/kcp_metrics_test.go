package metrics

import (
	"bytes"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/xtaci/kcp-go/v5"
)

// TestKCPMetricsTypedAndAtomic: every KCP_ series has a TYPE line right before it, the 30 historical names are all
// still there, and scraping while kcp-go updates the counters is race-free (run with -race).
func TestKCPMetricsTypedAndAtomic(t *testing.T) {
	s := new(kcp.Snmp)
	atomic.StoreUint64(&s.BytesSent, 7)
	atomic.StoreUint64(&s.CurrEstab, 3)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				atomic.AddUint64(&s.InPkts, 1)
			}
		}
	}()
	var b bytes.Buffer
	for i := 0; i < 50; i++ {
		b.Reset()
		write_kcp_metrics(&b, s)
	}
	close(stop)
	wg.Wait()
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	series := 0
	for i, l := range lines {
		if strings.HasPrefix(l, "KCP_") {
			series++
			name := strings.Fields(l)[0]
			if i == 0 || !strings.HasPrefix(lines[i-1], "# TYPE "+name+" ") {
				t.Fatalf("series %s has no TYPE line before it", name)
			}
		}
	}
	if series != 30 {
		t.Fatalf("%d KCP series, want the 30 historical ones", series)
	}
	for _, want := range []string{"KCP_BytesSent 7", "# TYPE KCP_CurrEstab gauge", "KCP_CurrEstab 3", "# TYPE KCP_InPkts counter", "KCP_FECFullShardSet ", "KCP_OOBPackets "} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("missing %q in\n%s", want, b.String())
		}
	}
}
