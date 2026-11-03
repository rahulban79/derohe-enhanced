// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8

package nat

import (
	"os"
	"testing"
)

// TestProbeLive asks the real default gateway (read-only: no mapping is created). Gated: DERO_NAT_PROBE_LIVE=1.
// It prints only the protocol, whether it answered and the external-address class, never an address.
func TestProbeLive(t *testing.T) {
	if os.Getenv("DERO_NAT_PROBE_LIVE") != "1" {
		t.Skip("set DERO_NAT_PROBE_LIVE=1 to probe the real gateway")
	}
	gw, err := DefaultGateway()
	if err != nil {
		t.Logf("default gateway: %v", err)
	}
	rs := Probe(gw, 0, Retry{}, nil)
	for _, r := range rs {
		t.Logf("protocol=%s available=%v class=%s error_kind=%s", r.Protocol, r.Available, r.ExternalClass, error_kind(r.Error))
	}
	t.Logf("verdict: %s", ProbeVerdict(rs))
}
