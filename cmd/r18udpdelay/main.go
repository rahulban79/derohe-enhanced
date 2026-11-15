// udpdelay: user-space WAN emulator for one KCP peer. Listens on -listen, forwards every datagram to -upstream and
// back, each direction delayed by -oneway (so RTT = 2*oneway) and dropped with probability -loss. Exits on stdin EOF
// or "exit".
package main

import (
	"bufio"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:35200", "")
	upstream := flag.String("upstream", "127.0.0.1:11011", "")
	oneway := flag.Duration("oneway", 50*time.Millisecond, "")
	loss := flag.Float64("loss", 0, "")
	flag.Parse()
	la, ua, err := resolve_pair(*listen, *upstream)
	if err != nil {
		panic(err)
	}
	ln, err := net.ListenUDP("udp", la)
	if err != nil {
		panic(err)
	}
	var mu sync.Mutex
	ups := map[string]*net.UDPConn{}
	var fwd, back, dropped int64
	// one FIFO per direction keeps datagram order (a fixed-delay link does not reorder)
	type pkt struct {
		due time.Time
		c   *net.UDPConn
		to  *net.UDPAddr
		b   []byte
		ctr *int64
	}
	fifo := make(chan pkt, 1<<16)
	go func() {
		for p := range fifo {
			time.Sleep(time.Until(p.due))
			if p.to == nil {
				p.c.Write(p.b)
			} else {
				p.c.WriteToUDP(p.b, p.to)
			}
			atomic.AddInt64(p.ctr, 1)
		}
	}()
	send := func(c *net.UDPConn, to *net.UDPAddr, b []byte, ctr *int64) {
		if *loss > 0 && rand.Float64() < *loss {
			atomic.AddInt64(&dropped, 1)
			return
		}
		fifo <- pkt{time.Now().Add(*oneway), c, to, b, ctr}
	}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := ln.ReadFromUDP(buf)
			if err != nil {
				return
			}
			mu.Lock()
			u, ok := ups[from.String()]
			if !ok {
				u, err = net.DialUDP("udp", nil, ua)
				if err != nil {
					mu.Unlock()
					continue
				}
				u.SetReadBuffer(4 << 20)
				ups[from.String()] = u
				go func(u *net.UDPConn, client *net.UDPAddr) {
					b := make([]byte, 65536)
					for {
						n, err := u.Read(b)
						if err != nil {
							return
						}
						send(ln, client, append([]byte{}, b[:n]...), &back)
					}
				}(u, from)
			}
			mu.Unlock()
			send(u, nil, append([]byte{}, buf[:n]...), &fwd)
		}
	}()
	ln.SetReadBuffer(4 << 20)
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		if sc.Text() == "exit" {
			break
		}
	}
	fmt.Printf("fwd %d back %d dropped %d\n", fwd, back, dropped)
}

// resolve_pair resolves -listen and -upstream. r31 (detector error-paths DF-error-paths-c2012f4b07 / -c0c880f6d6): the
// errors were discarded, so a malformed -listen made ListenUDP bind a random port and a malformed -upstream left
// every forward to a nil address, both silently.
func resolve_pair(listen, upstream string) (*net.UDPAddr, *net.UDPAddr, error) {
	la, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return nil, nil, fmt.Errorf("-listen %q: %w", listen, err)
	}
	ua, err := net.ResolveUDPAddr("udp", upstream)
	if err != nil {
		return nil, nil, fmt.Errorf("-upstream %q: %w", upstream, err)
	}
	return la, ua, nil
}
