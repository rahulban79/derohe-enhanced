package explorerlib

// Round 19 explorer hardening (the explorer is a separate binary; nothing here touches the node or consensus).
//
//  1. The server ran on http.ListenAndServe: no read/write/idle timeouts and the default 1 MiB header cap, on
//     0.0.0.0:8081 by default. A slow-loris client could hold connections (and goroutines) forever.
//  2. No security headers: pages could be framed (click-jacking the tx-proof form) and MIME-sniffed.
//  3. Request bodies were limited only by Go's 10 MiB urlencoded cap; the tx-proof POST needs a few hundred KiB.
//  4. Every "/" or "/page/N" hit re-rendered from scratch: 2x DERO.GetInfo + GetTxPool + up to 25 GetTransaction
//     + 10-12 GetBlock + one GetTransaction per block tx. Ten clients refreshing = ten times that load on derod.
//     Rendered pages are now reused for PAGE_CACHE_TTL (the chain moves every ~18 s) and at most
//     RENDER_CONCURRENCY renders run at once.
//  5. RPC calls used context.Background(): a hung daemon hung every handler goroutine forever.

import (
	"bytes"
	"context"
	"net/http"
	"sync"
	"time"
)

const MAX_REQUEST_BODY = 1 << 20 // 1 MiB: a raw tx for the proof form is far smaller
const PAGE_CACHE_TTL = 3 * time.Second
const PAGE_CACHE_MAX = 64
const RENDER_CONCURRENCY = 4
const RPC_CALL_TIMEOUT = 30 * time.Second

// CSP: templates use inline <script>/<style> and onclick handlers, so 'unsafe-inline' stays for those two; every
// other source is pinned to self and framing is refused.
const CONTENT_SECURITY_POLICY = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

func harden(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", CONTENT_SECURITY_POLICY)
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, MAX_REQUEST_BODY)
		}
		next.ServeHTTP(w, r)
	})
}

func new_http_server(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           harden(h),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      90 * time.Second, // a cold page is ~40 sequential RPC calls
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
}

type page_entry struct {
	body []byte
	at   time.Time
}

type page_cache_t struct {
	sync.Mutex
	m        map[int]page_entry
	inflight map[int]chan struct{} // one render per page at a time; other requests for it wait for that render
	slots    chan struct{}
	now      func() time.Time
}

func new_page_cache() *page_cache_t {
	return &page_cache_t{m: map[int]page_entry{}, inflight: map[int]chan struct{}{}, slots: make(chan struct{}, RENDER_CONCURRENCY), now: time.Now}
}

var page_cache = new_page_cache()

// get returns a fresh cached page or renders one with render, storing it on success. Concurrent requests for the
// same page share one render; errors are not cached (a waiter whose render failed renders itself).
func (pc *page_cache_t) get(ctx context.Context, page int, render func(int) ([]byte, error)) ([]byte, error) {
	for {
		pc.Lock()
		if e, ok := pc.m[page]; ok && pc.now().Sub(e.at) < PAGE_CACHE_TTL {
			pc.Unlock()
			return e.body, nil
		}
		wait, busy := pc.inflight[page]
		if !busy {
			pc.inflight[page] = make(chan struct{})
			pc.Unlock()
			break
		}
		pc.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	done := func() {
		pc.Lock()
		close(pc.inflight[page])
		delete(pc.inflight, page)
		pc.Unlock()
	}

	select {
	case pc.slots <- struct{}{}:
	case <-ctx.Done():
		done()
		return nil, ctx.Err()
	}
	body, err := render(page)
	<-pc.slots
	if err != nil {
		done()
		return nil, err
	}
	pc.Lock()
	if len(pc.m) >= PAGE_CACHE_MAX { // drop expired entries; if still full, start over (bounded memory)
		for k, e := range pc.m {
			if pc.now().Sub(e.at) >= PAGE_CACHE_TTL {
				delete(pc.m, k)
			}
		}
		if len(pc.m) >= PAGE_CACHE_MAX {
			pc.m = map[int]page_entry{}
		}
	}
	pc.m[page] = page_entry{body: body, at: pc.now()}
	pc.Unlock()
	done()
	return body, nil
}

// render_into executes a template into a buffer so a failing template never leaves a half-written page.
func render_into(name string, data interface{}) ([]byte, error) {
	var b bytes.Buffer
	if err := all_templates.ExecuteTemplate(&b, name, data); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
