package p2p

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"io"
	"testing"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/pbkdf2"
)

// a tuned pair (bigger window, listener buffers, both KCP profiles) must still carry data intact in both directions
func TestTunedKCPRoundTrip(t *testing.T) {
	if KCP_WINDOW < 32 || KCP_WINDOW > 1024 {
		t.Fatalf("KCP_WINDOW %d out of range", KCP_WINDOW)
	}
	key := pbkdf2.Key([]byte("t"), []byte("t"), 1024, 32, sha1.New)
	block, _ := kcp.NewAESBlockCrypt(key)
	for _, low := range []bool{false, true} {
		P2PLowLatency = low
		l, err := kcp.ListenWithOptions("127.0.0.1:0", block, 10, 3)
		if err != nil {
			t.Fatal(err)
		}
		tune_listener(l)
		payload := make([]byte, 1<<20)
		rand.Read(payload)
		done := make(chan []byte, 1)
		go func() {
			s, err := l.AcceptKCP()
			if err != nil {
				done <- nil
				return
			}
			tunekcp(s)
			got := make([]byte, len(payload))
			s.SetReadDeadline(time.Now().Add(30 * time.Second))
			if _, err := io.ReadFull(s, got); err != nil {
				done <- nil
				return
			}
			s.Write(got[:4096]) // echo a slice back
			done <- got
		}()
		c, err := kcp.DialWithOptions(l.Addr().String(), block, 10, 3)
		if err != nil {
			t.Fatal(err)
		}
		tunekcp(c)
		c.Write(payload)
		echo := make([]byte, 4096)
		c.SetReadDeadline(time.Now().Add(30 * time.Second))
		if _, err := io.ReadFull(c, echo); err != nil || !bytes.Equal(echo, payload[:4096]) {
			t.Fatalf("lowlatency=%v echo failed: %v", low, err)
		}
		if got := <-done; !bytes.Equal(got, payload) {
			t.Fatalf("lowlatency=%v payload corrupted", low)
		}
		c.Close()
		l.Close()
	}
	P2PLowLatency = false
}
