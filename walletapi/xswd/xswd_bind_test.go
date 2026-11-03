package xswd

import (
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/creachadair/jrpc2"
	"github.com/deroproject/derohe/walletapi"
)

func TestXSWDListenAddrs(t *testing.T) {
	if got := xswd_listen_addrs(44326, ""); !reflect.DeepEqual(got, []string{"127.0.0.1:44326", "[::1]:44326"}) {
		t.Fatalf("default bind %v, want loopback only", got)
	}
	if got := xswd_listen_addrs(44326, " 0.0.0.0 "); !reflect.DeepEqual(got, []string{"0.0.0.0:44326"}) {
		t.Fatalf("explicit bind %v", got)
	}
	AllowRemoteConnections = true
	defer func() { AllowRemoteConnections = false }()
	if got := xswd_listen_addrs(44326, ""); !reflect.DeepEqual(got, []string{":44326"}) {
		t.Fatalf("--xswd-allow-remote bind %v, want every interface", got)
	}
}

// The running server answers on loopback and not on the machine's LAN address.
func TestXSWDServerIsLoopbackOnly(t *testing.T) {
	const port = 44391
	os.Unsetenv("DERO_XSWD_BIND")
	w, err := walletapi.Create_Encrypted_Wallet_From_Recovery_Words("xswd_bind_test.db", "xswd", testWalletData[0].seed)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove("xswd_bind_test.db")
	server := NewXSWDServerWithPort(port, w, false, nil, func(*ApplicationData) bool { return false },
		func(*ApplicationData, *jrpc2.Request) Permission { return Deny })
	defer server.Stop()
	time.Sleep(500 * time.Millisecond)
	c, err := net.DialTimeout("tcp", "127.0.0.1:44391", 2*time.Second)
	if err != nil {
		t.Fatalf("loopback refused: %v", err)
	}
	c.Close()
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.IsLoopback() || ipn.IP.To4() == nil || ipn.IP.IsLinkLocalUnicast() {
			continue
		}
		if c, err := net.DialTimeout("tcp", net.JoinHostPort(ipn.IP.String(), "44391"), 2*time.Second); err == nil {
			c.Close()
			t.Fatalf("XSWD answers on the LAN address %s", ipn.IP)
		}
		return
	}
	t.Log("no non-loopback IPv4 address on this host: LAN half not exercised")
}

// TestXSWDServerHasHeaderTimeout: XSWD uses the wallet server limits (RPCWS-13).
func TestXSWDServerHasHeaderTimeout(t *testing.T) {
	w, err := walletapi.Create_Encrypted_Wallet_From_Recovery_Words("xswd_timeout_test.db", "xswd", testWalletData[0].seed)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove("xswd_timeout_test.db")
	server := NewXSWDServerWithPort(44393, w, false, nil, func(*ApplicationData) bool { return false },
		func(*ApplicationData, *jrpc2.Request) Permission { return Deny })
	defer server.Stop()
	if server.server.ReadHeaderTimeout <= 0 || server.server.IdleTimeout <= 0 || server.server.MaxHeaderBytes <= 0 {
		t.Fatalf("XSWD http.Server has no header/idle limits: %+v", server.server)
	}
}
