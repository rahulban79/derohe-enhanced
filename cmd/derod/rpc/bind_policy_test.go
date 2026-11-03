package rpc

import "testing"

func TestPprofAllowed(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	cases := []struct {
		bind string
		env  map[string]string
		want bool
	}{
		{"127.0.0.1:10102", nil, true}, // the live node: unchanged
		{"[::1]:10102", nil, true},
		{"127.0.0.1:10102", map[string]string{"DISABLE_RUNTIME_PROFILE": "1"}, false},
		{"0.0.0.0:10102", nil, false}, // public bind: off by default
		{"192.168.1.5:10102", nil, false},
		{"0.0.0.0:10102", map[string]string{"ENABLE_PUBLIC_RUNTIME_PROFILE": "1"}, true},
		{"0.0.0.0:10102", map[string]string{"ENABLE_PUBLIC_RUNTIME_PROFILE": "1", "DISABLE_RUNTIME_PROFILE": "1"}, false},
	}
	for _, c := range cases {
		if got := pprof_allowed(c.bind, env(c.env)); got != c.want {
			t.Errorf("pprof_allowed(%q,%v)=%v want %v", c.bind, c.env, got, c.want)
		}
	}
	if bind_is_loopback("0.0.0.0:10100") || !bind_is_loopback("127.0.0.1:10100") || bind_is_loopback("garbage") {
		t.Fatalf("bind_is_loopback wrong")
	}
}
