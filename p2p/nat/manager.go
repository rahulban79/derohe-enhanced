// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

package nat

import "context"
import "errors"
import "fmt"
import "io/ioutil"
import "net"
import "os"
import "os/exec"
import "runtime"
import "strconv"
import "strings"
import "sync"
import "time"

// Modes accepted by --p2p-nat.
const (
	ModeOff    = "off"
	ModeAuto   = "auto" // PCP, then NAT-PMP, then UPnP
	ModePCP    = "pcp"
	ModeNATPMP = "natpmp"
	ModeUPnP   = "upnp"
	ModeProbe  = "probe" // read-only: ask what the gateway supports, never map (probe.go)
)

func ValidMode(m string) bool {
	switch m {
	case ModeOff, ModeAuto, ModePCP, ModeNATPMP, ModeUPnP, ModeProbe:
		return true
	}
	return false
}

// Status is what GetSyncInfo reports.
type Status struct {
	Mode         string        `json:"mode"`
	Active       bool          `json:"active"`
	Protocol     string        `json:"protocol,omitempty"`
	Gateway      string        `json:"gateway,omitempty"`
	InternalPort int           `json:"internal_port"`
	ExternalIP   string        `json:"external_ip,omitempty"`
	ExternalPort int           `json:"external_port,omitempty"`
	LifetimeS    int64         `json:"lifetime_seconds,omitempty"`
	RenewedAt    int64         `json:"renewed_at,omitempty"` // unix seconds
	Renewals     uint64        `json:"renewals"`
	Failures     uint64        `json:"failures"`
	Error        string        `json:"error,omitempty"`
	Warning      string        `json:"warning,omitempty"`
	Probe        []ProbeResult `json:"probe,omitempty"`   // --p2p-nat=probe: what each protocol answered
	Verdict      string        `json:"verdict,omitempty"` // --p2p-nat=probe: the operator instruction (ProbeVerdict)
}

type Options struct {
	Mode         string
	InternalPort int
	Gateway      net.IP        // nil = discover
	GatewayPort  int           // 0 = PMPPort (tests use a loopback fake gateway)
	Lifetime     time.Duration // requested; 0 = DefaultLifetime
	Retry        Retry         // UDP protocols; zero = DefaultRetry
	UPnP         *UPnP         // nil = default discovery
	Log          func(msg string, kv ...interface{})
	// test hooks
	MinRenew   time.Duration // floor of the renew interval (default 30 s)
	RetryAfter time.Duration // after a failed attempt (default 2 min, doubling to 30 min)
}

const DefaultLifetime = time.Hour

// Manager keeps one mapping alive: renew at half its lifetime, retry with back-off on failure, unmap on Stop.
type Manager struct {
	opts    Options
	mu      sync.Mutex
	status  Status
	client  Client
	mapping *Mapping
	stop    chan struct{}
	done    chan struct{}
	once    sync.Once
}

func Start(opts Options) *Manager {
	if opts.Lifetime <= 0 {
		opts.Lifetime = DefaultLifetime
	}
	if opts.Retry.Tries == 0 {
		opts.Retry = DefaultRetry
	}
	if opts.MinRenew <= 0 {
		opts.MinRenew = 30 * time.Second
	}
	if opts.RetryAfter <= 0 {
		opts.RetryAfter = 2 * time.Minute
	}
	if opts.Log == nil {
		opts.Log = func(string, ...interface{}) {}
	}
	m := &Manager{opts: opts, stop: make(chan struct{}), done: make(chan struct{})}
	m.status = Status{Mode: opts.Mode, InternalPort: opts.InternalPort}
	if opts.Mode == ModeProbe {
		go m.probe()
		return m
	}
	go m.run()
	return m
}

func (m *Manager) Status() Status {
	if m == nil {
		return Status{Mode: ModeOff}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.status
}

// ExternalPort returns the mapped port while a mapping is active, else 0.
func (m *Manager) ExternalPort() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.status.Active {
		return m.status.ExternalPort
	}
	return 0
}

// candidates lists the clients to try, in order, for the configured mode.
func (m *Manager) candidates() ([]Client, error) {
	var out []Client
	mode := m.opts.Mode
	if mode == ModeAuto || mode == ModePCP || mode == ModeNATPMP {
		gw := m.opts.Gateway
		if gw == nil {
			var err error
			if gw, err = DefaultGateway(); err != nil && mode != ModeAuto {
				return nil, err
			}
		}
		if gw != nil {
			port := m.opts.GatewayPort
			if port == 0 {
				port = PMPPort
			}
			addr := &net.UDPAddr{IP: gw, Port: port}
			if mode == ModeAuto || mode == ModePCP {
				out = append(out, &PCP{Gateway: addr, Retry: m.opts.Retry})
			}
			if mode == ModeAuto || mode == ModeNATPMP {
				out = append(out, &NATPMP{Gateway: addr, Retry: m.opts.Retry})
			}
		}
	}
	if mode == ModeAuto || mode == ModeUPnP {
		u := m.opts.UPnP
		if u == nil {
			u = &UPnP{}
		}
		out = append(out, u)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("nat: no protocol available for mode %q", mode)
	}
	return out, nil
}

// establish creates a mapping with the first client that grants one.
func (m *Manager) establish() error {
	cands, err := m.candidates()
	if err != nil {
		return err
	}
	var errs []string
	for _, c := range cands {
		mp, err := c.Map(m.opts.InternalPort, m.opts.InternalPort, m.opts.Lifetime)
		if err == nil {
			m.mu.Lock()
			m.client, m.mapping = c, &mp
			m.mu.Unlock()
			return nil
		}
		errs = append(errs, c.Name()+": "+err.Error())
	}
	return errors.New(strings.Join(errs, "; "))
}

// renew extends the current mapping (PCP with its nonce; the others by re-requesting the same ports).
func (m *Manager) renew() error {
	m.mu.Lock()
	c, cur := m.client, m.mapping
	m.mu.Unlock()
	if c == nil || cur == nil {
		return m.establish()
	}
	var mp Mapping
	var err error
	if p, ok := c.(*PCP); ok {
		mp, err = p.Renew(*cur, m.opts.Lifetime)
	} else {
		mp, err = c.Map(cur.InternalPort, cur.ExternalPort, m.opts.Lifetime)
	}
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.mapping = &mp
	m.mu.Unlock()
	return nil
}

// warning flags a mapping that cannot make the node reachable: a non-public external address means another NAT
// (carrier-grade or a second router) sits between the gateway and the internet.
func warning(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return "gateway's external address " + ip.String() + " is not public: another NAT is upstream (double NAT / CGNAT), inbound peers still cannot reach this node"
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64 {
		return "gateway's external address " + ip.String() + " is carrier-grade NAT (100.64.0.0/10): inbound peers still cannot reach this node"
	}
	return ""
}

func (m *Manager) record(err error, renewal bool) time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.status.Active = false
		m.status.Failures++
		m.status.Error = err.Error()
		return 0
	}
	mp := m.mapping
	m.status.Active = true
	m.status.Error = ""
	m.status.Protocol = mp.Protocol
	m.status.Gateway = mp.Gateway
	m.status.ExternalPort = mp.ExternalPort
	if mp.ExternalIP != nil {
		m.status.ExternalIP = mp.ExternalIP.String()
	}
	m.status.Warning = warning(mp.ExternalIP)
	m.status.LifetimeS = int64(mp.Lifetime / time.Second)
	m.status.RenewedAt = time.Now().Unix()
	if renewal {
		m.status.Renewals++
	}
	return renew_interval(mp.Lifetime, m.opts.Lifetime, m.opts.MinRenew)
}

// renew_interval: half the granted lifetime (RFC 6886 3.3 / RFC 6887 11.2.1 recommend renewing well before
// expiry), never below floor; a permanent UPnP lease (0) is re-asserted at half the requested lifetime, which
// also restores it after a gateway reboot.
func renew_interval(granted, requested, floor time.Duration) time.Duration {
	d := granted / 2
	if granted <= 0 {
		d = requested / 2
	}
	if d < floor {
		d = floor
	}
	return d
}

// stopping reports whether Stop was called. run checks it after every establish/renew, which can take seconds on a
// slow gateway: a mapping made after Stop gave up waiting is still removed (verifier NL-01).
func (m *Manager) stopping() bool {
	select {
	case <-m.stop:
		return true
	default:
		return false
	}
}

func (m *Manager) run() {
	defer close(m.done)
	defer m.release() // the run goroutine owns the final unmap, whenever it ends
	backoff := m.opts.RetryAfter
	err := m.establish()
	if m.stopping() {
		return
	}
	wait := m.record(err, false)
	if err != nil {
		m.opts.Log("NAT port mapping failed; will retry", "mode", m.opts.Mode, "error", err.Error(), "retry_in", backoff.String())
		wait = backoff
	} else {
		st := m.Status()
		m.opts.Log("NAT port mapping active", "protocol", st.Protocol, "external", net.JoinHostPort(st.ExternalIP, strconv.Itoa(st.ExternalPort)), "lifetime_s", st.LifetimeS, "warning", st.Warning)
	}
	for {
		t := time.NewTimer(wait)
		select {
		case <-m.stop:
			t.Stop()
			return
		case <-t.C:
		}
		m.mu.Lock()
		had := m.mapping != nil
		m.mu.Unlock()
		if had {
			err = m.renew()
			if err != nil { // the gateway may have rebooted and lost state (or the nonce): start over
				m.mu.Lock()
				m.client, m.mapping = nil, nil
				m.mu.Unlock()
				err = m.establish()
			}
		} else {
			err = m.establish()
		}
		if m.stopping() {
			return
		}
		wait = m.record(err, had && err == nil)
		if err != nil {
			wait = backoff
			if backoff < 30*time.Minute {
				backoff *= 2
			}
			m.opts.Log("NAT port mapping renewal failed", "error", err.Error(), "retry_in", wait.String())
		} else {
			backoff = m.opts.RetryAfter
		}
	}
}

// probe runs the read-only gateway probe once (probe.go); there is never a mapping to renew or remove.
func (m *Manager) probe() {
	defer close(m.done)
	gw := m.opts.Gateway
	if gw == nil {
		gw, _ = DefaultGateway() // nil: Probe reports "no default gateway" for PCP/NAT-PMP and still tries UPnP
	}
	rs := Probe(gw, m.opts.GatewayPort, m.opts.Retry, m.opts.UPnP)
	v := ProbeVerdict(rs)
	m.mu.Lock()
	m.status.Probe, m.status.Verdict = rs, v
	m.mu.Unlock()
	m.opts.Log("NAT probe (read-only, nothing mapped)", "verdict", v)
}

// Stop ends renewal and deletes the mapping (bounded by timeout, so shutdown never hangs on a dead gateway).
// UNMAP_TIMEOUT bounds the final DeletePortMapping/zero-lifetime request.
var UNMAP_TIMEOUT = 3 * time.Second

// release removes the current mapping from the gateway (bounded wait) and marks the manager inactive.
func (m *Manager) release() {
	m.mu.Lock()
	c, mp := m.client, m.mapping
	m.client, m.mapping = nil, nil
	m.status.Active = false
	m.mu.Unlock()
	if c == nil || mp == nil {
		return
	}
	res := make(chan error, 1)
	go func() { res <- c.Unmap(*mp) }()
	t := time.NewTimer(UNMAP_TIMEOUT)
	defer t.Stop()
	select {
	case err := <-res:
		if err != nil {
			m.opts.Log("NAT unmap failed", "error", err.Error())
		} else {
			m.opts.Log("NAT port mapping removed", "protocol", mp.Protocol, "external_port", mp.ExternalPort)
		}
	case <-t.C:
		m.opts.Log("NAT unmap timed out", "protocol", mp.Protocol)
	}
}

// Stop ends the manager and waits up to timeout for it to remove the mapping. If the run goroutine is still inside a
// slow establish/renew, Stop returns and run removes the mapping itself as soon as that call returns.
func (m *Manager) Stop(timeout time.Duration) {
	if m == nil {
		return
	}
	m.once.Do(func() {
		close(m.stop)
		deadline := time.NewTimer(timeout)
		defer deadline.Stop()
		select {
		case <-m.done:
		case <-deadline.C:
			m.opts.Log("NAT manager did not stop in time; the mapping is removed when the pending gateway request returns")
		}
	})
}

// ---------------------------------------------------------------- default gateway discovery (stdlib only)

// DefaultGateway returns the IPv4 default gateway. Override with env DERO_NAT_GATEWAY.
func DefaultGateway() (net.IP, error) {
	if s := os.Getenv("DERO_NAT_GATEWAY"); s != "" {
		if ip := net.ParseIP(s).To4(); ip != nil {
			return ip, nil
		}
		return nil, fmt.Errorf("nat: DERO_NAT_GATEWAY %q is not an IPv4 address", s)
	}
	if b, err := ioutil.ReadFile("/proc/net/route"); err == nil {
		if ip := parse_proc_net_route(string(b)); ip != nil {
			return ip, nil
		}
	}
	var cmd []string
	switch runtime.GOOS {
	case "darwin", "freebsd", "openbsd", "netbsd", "dragonfly":
		cmd = []string{"/sbin/route", "-n", "get", "default"}
	case "windows":
		cmd = []string{os.Getenv("SystemRoot") + `\System32\ROUTE.EXE`, "print", "-4", "0.0.0.0"}
	}
	if cmd != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		out, err := exec.CommandContext(ctx, cmd[0], cmd[1:]...).Output() // absolute path: no $PATH lookup
		cancel()
		if err == nil {
			if ip := parse_route_output(string(out)); ip != nil {
				return ip, nil
			}
		}
	}
	return nil, errors.New("nat: default gateway not found (set DERO_NAT_GATEWAY)")
}

// parse_proc_net_route: Linux, the row with destination 00000000; gateway is little-endian hex.
func parse_proc_net_route(s string) net.IP {
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[1] != "00000000" {
			continue
		}
		v, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil || v == 0 {
			continue
		}
		return net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24)).To4()
	}
	return nil
}

// parse_route_output: BSD/macOS "gateway: a.b.c.d", Windows "0.0.0.0  0.0.0.0  a.b.c.d  ...".
func parse_route_output(s string) net.IP {
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "gateway:" {
			if ip := net.ParseIP(f[1]).To4(); ip != nil {
				return ip
			}
		}
		if len(f) >= 3 && f[0] == "0.0.0.0" && f[1] == "0.0.0.0" {
			if ip := net.ParseIP(f[2]).To4(); ip != nil {
				return ip
			}
		}
	}
	return nil
}
