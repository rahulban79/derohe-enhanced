package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/deroproject/derohe/cmd/dero-miner/gsplit"
)

// r22 splitpipe: duty caps, tuner verdicts, the feeder throttle / collect time and the skipped stale GPU SHAs are exported.
func TestMetricsR22Splitpipe(t *testing.T) {
	var m miner_metrics
	m.set_split(gsplit.Stats{ThrottleUs: 2500000, CollectUs: 1500000, StaleSHASkipped: 77})
	m.cpu_duty, m.gpu_duty, m.tuner_on, m.tuner_kept, m.tuner_reverted, m.tuner_void = 95, 100, true, 3, 2, 1
	var b bytes.Buffer
	write_miner_metrics(&b, m)
	s := b.String()
	for _, want := range []string{"dero_miner_cpu_duty_percent 95", "dero_miner_gpu_duty_percent 100",
		`dero_miner_duty_tuner_verdicts_total{verdict="kept"} 3`, `dero_miner_duty_tuner_verdicts_total{verdict="void"} 1`,
		"dero_miner_split_feeder_throttle_seconds_total 2.500", "dero_miner_split_collect_seconds_total 1.500",
		"dero_miner_split_stale_sha_skipped_total 77"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q", want)
		}
	}
	f := split_fields(gsplit.Stats{GPUMax: 95, ThrottleUs: 9000, CollectUs: 4000, StaleSHASkipped: 5}, gsplit.Stats{}, 60)
	got := map[string]interface{}{}
	for i := 0; i+1 < len(f); i += 2 {
		got[f[i].(string)] = f[i+1]
	}
	if got["gpu_max"] != 95 || got["feeder_throttle_ms"] != uint64(9) || got["collect_ms"] != uint64(4) || got["stale_sha_skipped"] != uint64(5) {
		t.Fatalf("split_fields r22 fields: %v", got)
	}
}
