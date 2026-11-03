package explorerlib

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHardenHeadersAndBodyCap(t *testing.T) {
	var read_err error
	h := harden(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, read_err = io.ReadAll(r.Body)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/tx/x", strings.NewReader(strings.Repeat("a", MAX_REQUEST_BODY+1))))
	if read_err == nil {
		t.Fatal("a body over MAX_REQUEST_BODY was read in full")
	}
	for k, want := range map[string]string{"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Content-Security-Policy": CONTENT_SECURITY_POLICY} {
		if got := rec.Header().Get(k); got != want {
			t.Fatalf("%s = %q, want %q", k, got, want)
		}
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/tx/x", strings.NewReader("txproof=abc")))
	if read_err != nil {
		t.Fatalf("small body rejected: %v", read_err)
	}
}

func TestHTTPServerHasTimeouts(t *testing.T) {
	s := new_http_server("127.0.0.1:0", http.NewServeMux())
	if s.ReadHeaderTimeout == 0 || s.ReadTimeout == 0 || s.WriteTimeout == 0 || s.IdleTimeout == 0 || s.MaxHeaderBytes == 0 {
		t.Fatalf("server without limits: %+v", s)
	}
}

func TestPageCacheSharesRendersAndExpires(t *testing.T) {
	pc := new_page_cache()
	now := time.Unix(1000, 0)
	var mu sync.Mutex
	pc.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	var renders int32
	render := func(p int) ([]byte, error) {
		atomic.AddInt32(&renders, 1)
		time.Sleep(10 * time.Millisecond)
		return []byte("page"), nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); pc.get(context.Background(), 5, render) }()
	}
	wg.Wait()
	if renders != 1 {
		t.Fatalf("%d renders for 20 concurrent requests of one page, want 1", renders)
	}
	mu.Lock()
	now = now.Add(PAGE_CACHE_TTL)
	mu.Unlock()
	pc.get(context.Background(), 5, render)
	if renders != 2 {
		t.Fatalf("expired page served from cache (renders %d)", renders)
	}
	if _, err := pc.get(context.Background(), 6, func(int) ([]byte, error) { return nil, errors.New("rpc down") }); err == nil {
		t.Fatal("error swallowed")
	}
	if _, ok := pc.m[6]; ok {
		t.Fatal("an error was cached")
	}
	for p := 0; p < 3*PAGE_CACHE_MAX; p++ {
		pc.get(context.Background(), 100+p, render)
	}
	if len(pc.m) > PAGE_CACHE_MAX {
		t.Fatalf("cache grew to %d entries, bound is %d", len(pc.m), PAGE_CACHE_MAX)
	}
}
