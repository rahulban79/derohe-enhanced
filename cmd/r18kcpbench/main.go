// r18kcpbench: measures the derod KCP transport (AES + FEC 10/3, exactly as p2p/controller.go dials) through a
// WAN emulator (udpdelay) for bulk throughput and small-message round trips, per tuning profile.
package main

import (
	"crypto/sha1"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/pbkdf2"
)

type profile struct {
	nodelay, interval, resend, nc int
	sndwnd, rcvwnd                int
	acknodelay                    bool
}

func tune(c *kcp.UDPSession, p profile) {
	c.SetACKNoDelay(p.acknodelay)
	c.SetNoDelay(p.nodelay, p.interval, p.resend, p.nc)
	if p.sndwnd > 0 {
		c.SetWindowSize(p.sndwnd, p.rcvwnd)
	}
	c.SetReadBuffer(1 << 20)
}

func main() {
	listen := flag.String("listen", "127.0.0.1:35600", "server bind")
	dial := flag.String("dial", "127.0.0.1:35601", "client dials this (the udpdelay front)")
	mode := flag.String("mode", "bulk", "bulk|rtt")
	size := flag.Int("size", 4<<20, "bulk bytes")
	n := flag.Int("n", 200, "rtt samples")
	cl := flag.String("client", "1,10,2,1,32,32,1", "nodelay,interval,resend,nc,sndwnd,rcvwnd,acknodelay")
	sv := flag.String("server", "1,10,2,1,32,32,1", "")
	flag.Parse()
	parse := func(s string) (p profile) {
		var a int
		fmt.Sscanf(s, "%d,%d,%d,%d,%d,%d,%d", &p.nodelay, &p.interval, &p.resend, &p.nc, &p.sndwnd, &p.rcvwnd, &a)
		p.acknodelay = a == 1
		return
	}
	cp, sp := parse(*cl), parse(*sv)
	key := pbkdf2.Key([]byte("bench"), []byte("bench"), 1024, 32, sha1.New)
	block, _ := kcp.NewAESBlockCrypt(key)
	l, err := kcp.ListenWithOptions(*listen, block, 10, 3)
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			s, err := l.AcceptKCP()
			if err != nil {
				return
			}
			tune(s, sp)
			go func(s *kcp.UDPSession) { // server: bulk -> send size bytes after a 4-byte request; rtt -> echo
				hdr := make([]byte, 4)
				for {
					if _, err := io.ReadFull(s, hdr); err != nil {
						return
					}
					want := int(binary.LittleEndian.Uint32(hdr))
					if want == 0 { // echo request of 64 bytes
						b := make([]byte, 64)
						io.ReadFull(s, b)
						s.Write(b)
						continue
					}
					buf := make([]byte, 64<<10)
					for sent := 0; sent < want; {
						k := len(buf)
						if want-sent < k {
							k = want - sent
						}
						s.Write(buf[:k])
						sent += k
					}
				}
			}(s)
		}
	}()
	c, err := kcp.DialWithOptions(*dial, block, 10, 3)
	if err != nil {
		panic(err)
	}
	tune(c, cp)
	hdr := make([]byte, 4)
	if *mode == "bulk" {
		binary.LittleEndian.PutUint32(hdr, uint32(*size))
		t0 := time.Now()
		c.Write(hdr)
		c.SetReadDeadline(time.Now().Add(120 * time.Second))
		if _, err := io.CopyN(io.Discard, c, int64(*size)); err != nil {
			fmt.Println("ERR", err)
			os.Exit(1)
		}
		el := time.Since(t0)
		st := kcp.DefaultSnmp.Copy()
		fmt.Printf("{\"mode\":\"bulk\",\"secs\":%.3f,\"KBps\":%.1f,\"retrans\":%d,\"lost\":%d,\"outpkts\":%d,\"inpkts\":%d}\n", el.Seconds(), float64(*size)/1024/el.Seconds(), st.RetransSegs, st.LostSegs, st.OutPkts, st.InPkts)
		return
	}
	var lat []float64
	msg := make([]byte, 64)
	for i := 0; i < *n; i++ {
		t0 := time.Now()
		c.Write(append(append([]byte{}, 0, 0, 0, 0), msg...))
		c.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.ReadFull(c, msg); err != nil {
			fmt.Println("ERR", err)
			os.Exit(1)
		}
		lat = append(lat, float64(time.Since(t0).Microseconds())/1000)
		time.Sleep(20 * time.Millisecond)
	}
	sort.Float64s(lat)
	m := 0.0
	for _, v := range lat {
		m += v
	}
	st := kcp.DefaultSnmp.Copy()
	fmt.Printf("{\"mode\":\"rtt\",\"p50_ms\":%.1f,\"p90_ms\":%.1f,\"p99_ms\":%.1f,\"mean_ms\":%.1f,\"outpkts\":%d,\"inpkts\":%d,\"retrans\":%d}\n", lat[len(lat)/2], lat[len(lat)*9/10], lat[len(lat)*99/100], m/float64(len(lat)), st.OutPkts, st.InPkts, st.RetransSegs)
}
