package main

// r24 getworkops: nodehealth against a fake derod (httptest), including derod's empty reply without Content-Type.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fake answers like derod: an empty 200 body without Content-Type: application/json (B38), else the canned result.
func fake(t *testing.T, results map[string]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Type") != "application/json" {
			return // 200, 0 bytes
		}
		b, _ := io.ReadAll(r.Body)
		var req struct{ Method string }
		json.Unmarshal(b, &req)
		res, ok := results[req.Method]
		if !ok {
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no such method","data":"`+req.Method+`"}}`)
			return
		}
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":`+res+`}`)
	}))
}

const synced = `{"status":"synced","reason":"ok","height":100,"topoheight":100,"tip_age_seconds":9.5,"lag_blocks":0,"peers_incoming":0,"peers_outgoing":13,"version":"3.6.0-153","chain_fingerprint":"v3 (upgraded chain, fork block e454090e)"}`

func check_run(t *testing.T, srv *httptest.Server, args ...string) (int, string) {
	t.Helper()
	var out, errb bytes.Buffer
	now := func() time.Time { return time.UnixMilli(1_000_000_000) }
	rc := run(append([]string{"-rpc=" + srv.URL + "/json_rpc"}, args...), &out, &errb, now)
	return rc, out.String() + errb.String()
}

func TestR24HealthSynced(t *testing.T) {
	srv := fake(t, map[string]string{"DERO.GetSyncInfo": synced})
	defer srv.Close()
	rc, out := check_run(t, srv)
	if rc != 0 || !strings.HasPrefix(out, "OK status=synced height=100") || !strings.Contains(out, "source=GetSyncInfo") {
		t.Fatalf("rc %d out %q", rc, out)
	}
	rc, out = check_run(t, srv, "-json")
	var r Report
	if err := json.Unmarshal([]byte(out), &r); err != nil || rc != 0 || !r.Healthy || r.Problems == nil || r.Info.PeersOutgoing != 13 {
		t.Fatalf("json rc %d %v %+v", rc, err, r)
	}
}

func TestR24HealthUnhealthy(t *testing.T) {
	for name, c := range map[string]struct {
		res, want string
		args      []string
	}{
		"syncing":   {strings.Replace(synced, `"status":"synced"`, `"status":"syncing"`, 1), "status syncing", nil},
		"old tip":   {strings.Replace(synced, `"tip_age_seconds":9.5`, `"tip_age_seconds":400`, 1), "tip block is 400 s old", nil},
		"no peers":  {strings.Replace(synced, `"peers_outgoing":13`, `"peers_outgoing":0`, 1), "0 peers", nil},
		"min peers": {synced, "13 peers (limit 20)", []string{"-min-peers=20"}},
		"v2 chain":  {strings.Replace(synced, `"v3 (upgraded`, `"v2 (remnant`, 1), "not the v3", nil},
	} {
		srv := fake(t, map[string]string{"DERO.GetSyncInfo": c.res})
		rc, out := check_run(t, srv, c.args...)
		srv.Close()
		if rc != 1 || !strings.HasPrefix(out, "UNHEALTHY") || !strings.Contains(out, c.want) {
			t.Errorf("%s: rc %d out %q", name, rc, out)
		}
	}
}

// a node without GetSyncInfo: tip age from the tip block's timestamp, not from GetInfo
func TestR24HealthFallbackTipAge(t *testing.T) {
	srv := fake(t, map[string]string{
		"DERO.GetInfo":            `{"height":50,"topoheight":50,"incoming_connections_count":1,"outgoing_connections_count":2,"uptime":7,"version":"3.5"}`,
		"DERO.GetLastBlockHeader": `{"block_header":{"height":50,"timestamp":999990000}}`, // 10 s before the fake now
	})
	defer srv.Close()
	rc, out := check_run(t, srv)
	if rc != 0 || !strings.Contains(out, "tip_age=10.0s") || !strings.Contains(out, "source=GetInfo+GetLastBlockHeader") || !strings.Contains(out, "status=unknown") {
		t.Fatalf("rc %d out %q", rc, out)
	}
	rc, out = check_run(t, srv, "-max-tip-age=5")
	if rc != 1 || !strings.Contains(out, "tip block is 10 s old") {
		t.Fatalf("stale fallback rc %d out %q", rc, out)
	}
}

// the tool always sends Content-Type (the fake answers nothing without it), and names an empty reply for what it is
func TestR24HealthContentTypeAndEmpty(t *testing.T) {
	srv := fake(t, map[string]string{"DERO.GetSyncInfo": synced})
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/json_rpc", "", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"DERO.GetSyncInfo"}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if len(b) != 0 {
		t.Fatal("fake must mimic derod's empty reply")
	}
	if rc, _ := check_run(t, srv); rc != 0 {
		t.Fatal("tool did not send Content-Type: application/json")
	}
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer empty.Close()
	if rc, out := check_run(t, empty); rc != 2 || !strings.Contains(out, "empty reply") || !strings.Contains(out, "B38") {
		t.Fatalf("empty: rc %d out %q", rc, out)
	}
}

func TestR24HealthDownAndErrors(t *testing.T) {
	srv := fake(t, nil)
	url := srv.URL
	srv.Close()
	var out, errb bytes.Buffer
	if rc := run([]string{"-rpc=" + url + "/json_rpc", "-timeout=1s"}, &out, &errb, time.Now); rc != 2 || !strings.HasPrefix(out.String(), "DOWN") {
		t.Fatalf("down: rc %d %q", rc, out.String())
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"internal"}}`)
	}))
	defer bad.Close()
	if rc, out := check_run(t, bad); rc != 2 || !strings.Contains(out, "DERO.GetSyncInfo: -32000") {
		t.Fatalf("rpc error (not 'no such method') must not fall back: rc %d %q", rc, out)
	}
}
