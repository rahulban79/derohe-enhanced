package p2p

import (
	"net"
	"sync"
	"testing"

	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
)

// discovery concurrency-01: update() is called from rpc2 handlers, pings and broadcasts at the same time; under
// -race the clock ring and StateHash must not tear.
func TestConcurrentUpdateIsRaceFree(t *testing.T) {
	c := &Connection{logger: globals.Logger}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				var common Common_Struct
				common.Height, common.TopoHeight = int64(i), int64(i)
				common.Top_Version = 3
				common.StateHash = crypto.Hash{byte(g), byte(i)}
				common.T0, common.T1, common.T2 = 1000, 1500+int64(g), 1600+int64(i)
				c.update(&common)
				_ = c.state_hash()
			}
		}(g)
	}
	wg.Wait()
}

type fake_addr string

func (a fake_addr) Network() string { return "udp" }
func (a fake_addr) String() string  { return string(a) }

// discovery concurrency-03: exit() must take the connection out of the pool at once, and only that connection.
func TestExitRemovesOnlyItself(t *testing.T) {
	c1, s1 := net.Pipe()
	c2, s2 := net.Pipe()
	defer s1.Close()
	defer s2.Close()
	a := &Connection{Addr: fake_addr("203.0.113.7:11011"), Conn: c1, ConnTls: c1, Client: nil}
	b := &Connection{Addr: fake_addr("203.0.113.7:11011"), Conn: c2, ConnTls: c2, Client: nil}
	connection_map.Store(Address(b), b) // the newer connection for the same IP holds the slot
	a.exit()                            // an older one exiting must not remove it
	if v, ok := connection_map.Load(Address(b)); !ok || v.(*Connection) != b {
		t.Fatal("exit() of an older connection removed the newer one for the same IP")
	}
	b.exit()
	if _, ok := connection_map.Load(Address(b)); ok {
		t.Fatal("exit() left the connection in connection_map")
	}
}
