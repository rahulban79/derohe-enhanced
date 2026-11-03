package rpc

// RPC/websocket hardening and push features (Round 19). Everything here is local policy of the daemon's HTTP
// listener: nothing is consensus-visible, nothing changes for a client on loopback unless it opts in.
//
//   - http.Server timeouts: the listener had none, so a client sending a header one byte a minute (slowloris)
//     held a goroutine and a socket forever.
//   - websocket pushes: Block and Height were sent by two goroutines that each walked every client in turn and
//     wrote synchronously, with no write deadline. One client that stopped reading blocked jrpc2's per-connection
//     lock forever and, being visited in turn, every client after it never got another notification. Now each
//     client gets its own goroutine, at most one bundle in flight per client, and a write deadline.
//   - per-method metrics: a series was created for whatever method name a client sent, including unknown ones,
//     so a client could grow the metrics set without bound. Only registered method names are counted now.
//   - per-IP limits for non-loopback clients only: websocket connections, in-flight HTTP requests, batch length.
//   - DERO.Subscribe: opt-in BlockInfo/MiniBlock events with payloads, for wallets and explorers.
//   - GET /health: 200 when synced, 503 otherwise, with the tip age (GetInfo cannot show a lagging node).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/VictoriaMetrics/metrics"
	"github.com/creachadair/jrpc2"
	"github.com/creachadair/jrpc2/code"
	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/glue/httpguard"
	dmetrics "github.com/deroproject/derohe/metrics"
	"github.com/deroproject/derohe/p2p"
)

// HTTP listener timeouts. ReadHeaderTimeout bounds only the request header; net/http clears the read deadline once
// the header is in (ReadTimeout stays 0), so long uploads and hijacked websockets are unaffected (tested).
var RPC_READ_HEADER_TIMEOUT = 10 * time.Second
var RPC_IDLE_TIMEOUT = 120 * time.Second

const RPC_MAX_HEADER_BYTES = 64 << 10

// WS_WRITE_TIMEOUT bounds one websocket message write (a response or a push). 60 s moves a 32 MiB message at ~4.5 Mbit/s.
var WS_WRITE_TIMEOUT = 60 * time.Second

// Limits for clients that are not on loopback. Loopback (wallets, miners, explorers on this machine, or a local
// reverse proxy) is never limited.
const WS_MAX_CONNS_PER_IP = 64
const HTTP_MAX_INFLIGHT_PER_IP = 32
const HTTP_MAX_BATCH_REMOTE = 256

func new_rpc_http_server(addr string, h http.Handler) *http.Server {
	return &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: RPC_READ_HEADER_TIMEOUT,
		IdleTimeout: RPC_IDLE_TIMEOUT, MaxHeaderBytes: RPC_MAX_HEADER_BYTES}
}

// ---- per-IP limits --------------------------------------------------------------------------------------------

// FOREIGN_LIMIT_KEY: every cross-site (foreign Origin) loopback client shares ONE limiter key, so the per-IP caps
// (WS_MAX_CONNS_PER_IP websockets, HTTP_MAX_INFLIGHT_PER_IP requests) are node-wide caps for all of them together.
// r20 merge (SEC20-02 review): keyed by the raw Origin, one page could frame a.evil.example, b.evil.example, ... and
// get 64 sockets for each.
const FOREIGN_LIMIT_KEY = "foreign-origin"

// rpc_allowed_origins holds DERO_RPC_ALLOWED_ORIGINS (set by rpc_guard): Origins treated as this machine.
var rpc_allowed_origins atomic.Value // []string

// foreign_origin reports a cross-site browser caller, except for Origins the operator listed.
func foreign_origin(r *http.Request) bool {
	allow, _ := rpc_allowed_origins.Load().([]string)
	return httpguard.ForeignOriginExcept(r, allow)
}

// remote_ip returns the key the per-IP limits count under, and whether the caller is exempt from them.
// r20: a loopback connection that a browser opened for a page from another site (foreign Origin header) is not a
// local program: it is limited like a remote client, under FOREIGN_LIMIT_KEY, so web pages together cannot hold
// more than the per-IP caps on a node they merely found on 127.0.0.1.
func remote_ip(r *http.Request) (ip string, loopback bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	p := net.ParseIP(host)
	loopback = p != nil && p.IsLoopback()
	if loopback && foreign_origin(r) {
		return FOREIGN_LIMIT_KEY, false
	}
	// r23: an IPv6 caller counts by its /64 (one end site holds the whole /64, so per-/128 caps were per-connection)
	return abuse_key(host), loopback
}

// ---- Host / Origin guard (r20) -----------------------------------------------------------------------------------

var rpc_guard_refused = map[string]*metrics.Counter{
	httpguard.REASON_HOST:   dmetrics.Set.GetOrCreateCounter(`rpc_guard_refused_total{reason="host"}`),
	httpguard.REASON_ORIGIN: dmetrics.Set.GetOrCreateCounter(`rpc_guard_refused_total{reason="origin"}`),
}

// rpc_guard wraps the RPC mux (r20). On a loopback --rpc-bind a request whose Host is not this machine is refused
// (DNS rebinding: measured on the live r19 node, Host "rebind.evil.example" read DERO.GetPeerInfo and
// /debug/pprof/cmdline). A cross-site browser request (foreign Origin) may only open /ws, as web wallets do; there it
// is limited like a remote client and refused the local-only methods (caller_is_foreign). Elsewhere it is refused:
// /json_rpc never worked cross-site anyway (the bridge answers 415 to a CORS-simple body and nothing answers the
// preflight), and /metrics, /dashboard, /debug/pprof, /health are for this machine.
// DERO_RPC_ALLOWED_ORIGINS (comma list, e.g. "chrome-extension://<id>,file://") makes those Origins local: they reach
// every path, are not limited and may call the local-only methods. Unset (the default) changes nothing.
func rpc_guard(bind string, mux http.Handler, getenv func(string) string) http.Handler {
	origins := httpguard.ParseOrigins(getenv("DERO_RPC_ALLOWED_ORIGINS"))
	rpc_allowed_origins.Store(origins)
	return httpguard.Guard(mux, httpguard.Policy{
		LoopbackBind: bind_is_loopback(bind),
		AllowHosts:   httpguard.ParseList(getenv("DERO_RPC_ALLOWED_HOSTS")),
		AllowOrigins: origins,
		ForeignOK:    func(path string) bool { return path == "/ws" },
		OnReject: func(reason string) {
			if c := rpc_guard_refused[reason]; c != nil {
				c.Inc()
			}
		},
	})
}

// caller_is_foreign reports whether a method runs for a websocket a cross-site page opened. HTTP bridge calls are
// never foreign: rpc_guard refuses cross-site /json_rpc before the bridge.
func caller_is_foreign(ctx context.Context) bool {
	if s := server_of(ctx); s != nil {
		if v, ok := client_connections.Load(s); ok {
			return v.(*ws_client).foreign
		}
	}
	return false
}

// server_of is jrpc2.ServerFromContext without its panic on a context that no server made (direct Go calls).
func server_of(ctx context.Context) (s *jrpc2.Server) {
	defer func() { recover() }()
	return jrpc2.ServerFromContext(ctx)
}

func refuse_foreign(ctx context.Context, method string) error {
	if caller_is_foreign(ctx) {
		return &jrpc2.Error{Code: code.InvalidRequest, Message: method + " is not served to cross-site (foreign Origin) websockets"}
	}
	return nil
}

type ip_limiter struct {
	mu  sync.Mutex
	n   map[string]int
	max int
}

func new_ip_limiter(max int) *ip_limiter { return &ip_limiter{n: map[string]int{}, max: max} }

func (l *ip_limiter) acquire(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.n[ip] >= l.max {
		return false
	}
	l.n[ip]++
	return true
}

func (l *ip_limiter) release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.n[ip] <= 1 {
		delete(l.n, ip)
	} else {
		l.n[ip]--
	}
}

var ws_conn_limit = new_ip_limiter(WS_MAX_CONNS_PER_IP)
var http_inflight_limit = new_ip_limiter(HTTP_MAX_INFLIGHT_PER_IP)

// batch_len reports how many requests a JSON-RPC body holds (1 for a single object).
func batch_len(body []byte) (int, error) {
	b := bytes.TrimLeft(body, " \t\r\n")
	if len(b) == 0 || b[0] != '[' {
		return 1, nil
	}
	var msgs []json.RawMessage
	if err := json.Unmarshal(b, &msgs); err != nil {
		return 0, err
	}
	return len(msgs), nil
}

// json_rpc_handler serves POST /json_rpc. Loopback goes straight to the bridge as before.
func json_rpc_handler(w http.ResponseWriter, req *http.Request) {
	req.Body = http.MaxBytesReader(w, req.Body, RPC_READ_LIMIT) // upstream read request bodies of any size (bind_policy.go)
	ip, loopback := remote_ip(req)
	if !http_request_shape_ok(w, req, ip, loopback) { // r24 (B38): 405/415 now carry a JSON-RPC error body (r24_rpcws.go)
		return
	}
	if !loopback {
		if !http_inflight_limit.acquire(ip) {
			dmetrics.Set.GetOrCreateCounter("rpc_limited_total").Inc()
			http.Error(w, "too many concurrent requests from this address", http.StatusTooManyRequests)
			return
		}
		defer http_inflight_limit.release(ip)
		body, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		if n, err := batch_len(body); err == nil && n > HTTP_MAX_BATCH_REMOTE {
			dmetrics.Set.GetOrCreateCounter("rpc_limited_total").Inc()
			http.Error(w, fmt.Sprintf("batch of %d requests exceeds %d", n, HTTP_MAX_BATCH_REMOTE), http.StatusRequestEntityTooLarge)
			return
		}
		items, err := remote_body_items(body) // r23c: per-call item bounds; r24: per-body total + item counts (B29)
		if err != nil {
			answer_bound_refusal(w, ip, err) // r23c verify: scored like any remote -32602 reply
			return
		}
		req.Body = io.NopCloser(bytes.NewReader(body)) // malformed JSON is left for the bridge to answer as before
		if !abuse_exempt(ip, false) && rpc_abuse.is_enabled() {
			serve_remote_json_rpc(w, req, ip, body, items) // r23: call cost + behaviour score (rpc_abuse.go); r24: items paid
			return
		}
		if methods, err := request_methods(body); err == nil && any_reserved(methods) { // r23b: guard off, still no built-ins
			write_method_not_found(w)
			return
		}
	}
	translate_http_to_jsonrpc_and_vice_versa(w, req)
}

// ---- websocket clients and pushes ------------------------------------------------------------------------------

const (
	SUB_BLOCKINFO uint32 = 1 << iota
	SUB_MINIBLOCK
	SUB_TXPOOL // r21: mempool added/removed txids (ws_tx_events.go)
	SUB_REORG  // r23b: replaced topoheights (reorg_events.go)
)

const SUB_ALL = SUB_BLOCKINFO | SUB_MINIBLOCK | SUB_TXPOOL | SUB_REORG

var sub_names = map[string]uint32{"BlockInfo": SUB_BLOCKINFO, "MiniBlock": SUB_MINIBLOCK, "TxPool": SUB_TXPOOL, "Reorg": SUB_REORG}

// ws_client is the value stored in client_connections for each websocket (the key stays its *jrpc2.Server).
type ws_client struct {
	conn         *websocket.Conn              // closed when a push cannot be written, which ends the jrpc2 server
	subs         uint32                       // DERO.Subscribe bits
	q_block      push_queue                   // r23c: Block/Height/BlockInfo(/Reorg) bundles, in order, one write at a time
	q_mini       push_queue                   // r23c: MiniBlock pushes
	q_pool       push_queue                   // r23c: TxPool diffs (was busy_pool)
	foreign      bool                         // opened by a cross-site page (foreign Origin); set before the server starts (r20)
	limiter      *rate.Limiter                // per-socket call budget, only for foreign sockets (r21, ws_foreign_rate.go)
	node_limiter *rate.Limiter                // shared budget: loopback-foreign sockets only (foreign_node_bucket)
	busy_tx      int32                        // 1 while a TxStatus push is being written (r21, ws_tx_events.go)
	watch_mu     sync.Mutex                   // guards watch and watch_closed
	watch_closed bool                         // set by drop_watches when the socket closes
	watch        map[crypto.Hash]*watch_entry // DERO.WatchTx entries (r21)
	abuse_key    string                       // r23: rpc_abuse key of a remote socket; "" = loopback/exempt (rpc_abuse.go)
	ban_once     sync.Once                    // r23: close_banned runs once
	items_held   atomic.Int64                 // r24: txids/keys in this socket's running calls (admit_call_items)
}

// new_ws_client builds the client record of a new /ws connection; a foreign one gets its call budget (r21) and, if
// it arrived over loopback (ip == FOREIGN_LIMIT_KEY), the shared node budget too (r21 merge, RPCWS21-A fix).
func new_ws_client(conn *websocket.Conn, foreign bool, ip string) *ws_client {
	c := &ws_client{conn: conn, foreign: foreign}
	if foreign {
		c.limiter = new_foreign_limiter()
		c.node_limiter = foreign_node_bucket(ip)
	}
	return c
}

var ws_push_skipped = dmetrics.Set.GetOrCreateCounter("rpc_ws_push_skipped_total")
var ws_push_queued = dmetrics.Set.GetOrCreateCounter("rpc_ws_push_queued_total") // r23c: written after the previous one finished

// WS_PUSH_QUEUE bounds the Block (or MiniBlock) pushes waiting behind the one being written to one client (r23c).
// Blocks come every ~18 s and a bundle is a few hundred bytes, so a reading client never fills it; a client that
// stopped reading holds at most this many closures (sharing one event value) until its write deadline closes it.
const WS_PUSH_QUEUE = 8

// push_queue serialises one push class of one client (r23c). Before, a push that found the previous one of its class
// still being written was dropped: a healthy client that was merely busy for a moment (the r19 test re-pushed until
// its Block arrived) lost that block's Block/Height bundle, so a wallet woke only at its next 5 s tick, a Reorg event
// in the dropped bundle was lost, and a dropped TxPool diff lost its txids for good (the next diff is computed
// against the pool the dropped one already advanced past). Now a push waits its turn; only past WS_PUSH_QUEUE is the
// OLDEST waiting push dropped (counted in rpc_ws_push_skipped_total), and the next push written is told so (lost),
// so the newest state is always delivered and pushes stay in order.
type push_queue struct {
	mu      sync.Mutex
	running bool
	lost    bool // a push was dropped since the last one written
	head, n int  // ring of waiting pushes: buf[head], ..., buf[(head+n-1)%WS_PUSH_QUEUE]
	buf     [WS_PUSH_QUEUE]push_item
}

// push_fn writes one push; lost says older pushes of the class were dropped since the last one written.
type push_fn func(s *jrpc2.Server, c *ws_client, lost bool) error

// push_item is one waiting push. The send function is shared by every client of one fan-out, so queueing a push
// allocates nothing (a fixed ring, no per-client closure): the r23c measurement of a closure-and-slice version was
// 302 allocs per 100-client fan-out against 101 for the r19 skip (evidence/ab_push.txt).
type push_item struct {
	s    *jrpc2.Server
	send push_fn
}

// push enqueues one push and reports whether the caller must start the writer (no write was in progress).
func (pq *push_queue) push(s *jrpc2.Server, send push_fn) (start bool) {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	if pq.n >= WS_PUSH_QUEUE { // drop the OLDEST waiting push
		pq.buf[pq.head] = push_item{}
		pq.head = (pq.head + 1) % WS_PUSH_QUEUE
		pq.n--
		pq.lost = true
		ws_push_skipped.Inc()
	}
	pq.buf[(pq.head+pq.n)%WS_PUSH_QUEUE] = push_item{s: s, send: send}
	pq.n++
	if pq.running {
		ws_push_queued.Inc()
		return false
	}
	pq.running = true
	return true
}

// next pops the oldest waiting push and whether pushes were dropped before it; ok=false (and the writer stops) when
// none is left. abort drops the rest.
func (pq *push_queue) next(abort bool) (it push_item, lost, ok bool) {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	if abort || pq.n == 0 {
		pq.buf, pq.head, pq.n, pq.running = [WS_PUSH_QUEUE]push_item{}, 0, 0, false
		return push_item{}, false, false
	}
	it, lost = pq.buf[pq.head], pq.lost
	pq.buf[pq.head], pq.lost = push_item{}, false
	pq.head = (pq.head + 1) % WS_PUSH_QUEUE
	pq.n--
	return it, lost, true
}

// drain writes the queued pushes one at a time; a failed write closes the socket (as before) and drops the rest.
func (pq *push_queue) drain(c *ws_client) {
	failed := false
	for it, lost, ok := pq.next(false); ok; it, lost, ok = pq.next(failed) {
		func() {
			defer globals.Recover(2)
			if err := it.send(it.s, c, lost); err != nil {
				failed = true
				if c.conn != nil && !errors.Is(err, jrpc2.ErrConnClosed) {
					c.conn.Close()
				}
			}
		}()
	}
}

// notify_clients sends to every client (or every client subscribed to need): the Block or the MiniBlock class.
func notify_clients(need uint32, mini bool, send func(*jrpc2.Server, *ws_client) error) {
	pick := func(c *ws_client) *push_queue { return &c.q_block }
	if mini {
		pick = func(c *ws_client) *push_queue { return &c.q_mini }
	}
	notify_clients_q(need, pick, func(s *jrpc2.Server, c *ws_client, _ bool) error { return send(s, c) })
}

// notify_clients_q queues send on the class queue pick returns, for every client subscribed to need (0: all). Each
// client's pushes of a class are written in order by one goroutine at a time, so a client that stops reading blocks
// only itself, and its write deadline closes it.
func notify_clients_q(need uint32, pick func(*ws_client) *push_queue, send push_fn) {
	client_connections.Range(func(k, v interface{}) bool {
		s, c := k.(*jrpc2.Server), v.(*ws_client)
		if need != 0 && atomic.LoadUint32(&c.subs)&need == 0 {
			return true
		}
		pq := pick(c)
		if pq.push(s, send) {
			go pq.drain(c)
		}
		return true
	})
}

func any_subscriber(need uint32) (found bool) {
	client_connections.Range(func(k, v interface{}) bool {
		found = atomic.LoadUint32(&v.(*ws_client).subs)&need != 0
		return !found
	})
	return
}

type BlockInfo_Event struct {
	Height         int64  `json:"height"`
	TopoHeight     int64  `json:"topoheight"`
	Hash           string `json:"hash"`
	TipTimestampMs uint64 `json:"tip_timestamp_ms"`
	ReorgSeq       uint64 `json:"reorg_seq,omitempty"` // r23b: Reorg events so far; a jump without a Reorg push = one was missed
}

type MiniBlock_Event struct {
	Height     int64 `json:"height"`     // chain height the miniblocks build on
	MiniBlocks int   `json:"miniblocks"` // miniblocks currently in the pool
}

// push_block sends the legacy Block and Height notifications (nil params, unchanged) to every client and BlockInfo
// to subscribers. info is computed only when some client subscribed.
func push_block(info func() BlockInfo_Event) { push_block_ev(info, nil) }

// push_block_ev is push_block with the reorg this block caused (nil: none). Reorg goes first in the bundle, so a
// subscriber rewinds before it re-reads the new tip (r23b).
func push_block_ev(info func() BlockInfo_Event, reorg *Reorg_Event) {
	var ev BlockInfo_Event
	if any_subscriber(SUB_BLOCKINFO) {
		ev = info()
	}
	notify_clients(0, false, func(s *jrpc2.Server, c *ws_client) error {
		if reorg != nil && atomic.LoadUint32(&c.subs)&SUB_REORG != 0 {
			if err := s.Notify(context.Background(), "Reorg", reorg); err != nil {
				return err
			}
		}
		if err := s.Notify(context.Background(), "Block", nil); err != nil {
			return err
		}
		if err := s.Notify(context.Background(), "Height", nil); err != nil {
			return err
		}
		if atomic.LoadUint32(&c.subs)&SUB_BLOCKINFO != 0 {
			return s.Notify(context.Background(), "BlockInfo", ev)
		}
		return nil
	})
}

func push_miniblock(info func() MiniBlock_Event) {
	if !any_subscriber(SUB_MINIBLOCK) {
		return
	}
	ev := info()
	notify_clients(SUB_MINIBLOCK, true, func(s *jrpc2.Server, c *ws_client) error {
		return s.Notify(context.Background(), "MiniBlock", ev)
	})
}

func chain_block_info() BlockInfo_Event {
	top := chain.Get_Top_ID()
	return BlockInfo_Event{Height: chain.Get_Height(), TopoHeight: chain.Load_TOPO_HEIGHT(), Hash: top.String(),
		TipTimestampMs: chain.Load_Block_Timestamp(top), ReorgSeq: reorg_state.seq()}
}

func chain_miniblock_info() MiniBlock_Event {
	return MiniBlock_Event{Height: chain.Get_Height(), MiniBlocks: chain.MiniBlocks.Count()}
}

type Subscribe_Params struct {
	Events []string `json:"events"`
}

type Subscribe_Result struct {
	Events []string `json:"events"`
	Status string   `json:"status"`
}

func parse_subscriptions(events []string) (bits uint32, names []string, err error) {
	for _, e := range events {
		b, ok := sub_names[e]
		if !ok {
			return 0, nil, &jrpc2.Error{Code: code.InvalidParams, Message: fmt.Sprintf("unknown event %q (known: BlockInfo, MiniBlock, Reorg, TxPool)", e)}
		}
		if bits&b == 0 {
			names = append(names, e)
		}
		bits |= b
	}
	sort.Strings(names)
	return
}

// Subscribe replaces this websocket's event set; an empty list unsubscribes. Block and Height keep being sent to
// every websocket client as before, so existing clients see no change.
func Subscribe(ctx context.Context, p Subscribe_Params) (result Subscribe_Result, err error) {
	bits, names, err := parse_subscriptions(p.Events)
	if err != nil {
		return result, err
	}
	v, ok := client_connections.Load(jrpc2.ServerFromContext(ctx)) // the HTTP bridge's server is never in the map
	if !ok {
		return result, &jrpc2.Error{Code: code.InvalidRequest, Message: "subscriptions need a websocket connection (/ws)"}
	}
	atomic.StoreUint32(&v.(*ws_client).subs, bits)
	if names == nil {
		names = []string{}
	}
	return Subscribe_Result{Events: names, Status: "OK"}, nil
}

// ---- per-method metrics ----------------------------------------------------------------------------------------

type method_metrics struct {
	duration *metrics.Histogram
	total    *metrics.Counter
	errors   *metrics.Counter
	out      *metrics.Counter
}

var method_metrics_map sync.Map // registered method name -> *method_metrics, created on its first call

// metrics_for returns the cached series of a registered method, nil for any other name. Before, every response did
// three string concatenations and three locked map lookups, and an unknown method created three new series.
// Series names (r19 merge with observability OBS-02): Prometheus-valid, the method as a label. The old
// "<method>_total" put a '.' (DERO.GetInfo) in the metric NAME, which VictoriaMetrics accepts but the Prometheus text
// parser rejects, failing the whole scrape. Renamed: <m>_duration_histogram_seconds -> rpc_request_duration_seconds,
// <m>_total -> rpc_requests_total, <m>_total_out_bytes -> rpc_response_bytes_total, new rpc_request_errors_total,
// all {method="<m>"}; unknown names go to rpc_unknown_method_total (rpc_method_label, node_metrics.go).
func metrics_for(method string) *method_metrics {
	if v, ok := method_metrics_map.Load(method); ok {
		return v.(*method_metrics)
	}
	if rpc_method_label(method) == "" {
		return nil
	}
	l := `{method="` + method + `"}`
	v, _ := method_metrics_map.LoadOrStore(method, &method_metrics{
		duration: dmetrics.Set.GetOrCreateHistogram("rpc_request_duration_seconds" + l),
		total:    dmetrics.Set.GetOrCreateCounter("rpc_requests_total" + l),
		errors:   dmetrics.Set.GetOrCreateCounter("rpc_request_errors_total" + l),
		out:      dmetrics.Set.GetOrCreateCounter("rpc_response_bytes_total" + l)})
	return v.(*method_metrics)
}

// response_size is len(resp.MarshalJSON()) without building the response a second time (jrpc2's toJSON layout).
func response_size(resp *jrpc2.Response) int {
	n := len(`{"jsonrpc":"2.0"}`)
	if id := resp.ID(); id != "" {
		n += len(`,"id":`) + len(id)
	}
	if e := resp.Error(); e != nil {
		if b, err := json.Marshal(e); err == nil {
			n += len(`,"error":`) + len(b)
		}
	} else if r := resp.ResultString(); r != "" {
		n += len(`,"result":`) + len(r)
	}
	return n
}

// ---- health -----------------------------------------------------------------------------------------------------

type Health_Result struct {
	Status        string  `json:"status"`
	Reason        string  `json:"reason"`
	Height        int64   `json:"height"`
	TopoHeight    int64   `json:"topoheight"`
	TipAgeSeconds float64 `json:"tip_age_seconds"`
	Peers         uint64  `json:"peers"`
	Version       string  `json:"version"`
}

func health_http_code(status string) int {
	if status == "synced" {
		return http.StatusOK
	}
	return http.StatusServiceUnavailable
}

// health serves GET /health: the GetSyncInfo verdict without its counters, as an HTTP status a load balancer or
// monitor can act on.
func health(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	}()
	var res Health_Result
	res.Height = chain.Get_Height()
	res.TopoHeight = chain.Load_TOPO_HEIGHT()
	top := chain.Get_Top_ID()
	res.TipAgeSeconds = float64(time.Now().UnixMilli()-int64(chain.Load_Block_Timestamp(top))) / 1000
	median, _ := p2p.Best_Peer_Height()
	in, out := p2p.Peer_Direction_Count()
	res.Peers = in + out
	var lag int64
	if median > 0 {
		lag = median - res.Height
	}
	res.Status, res.Reason = classify_sync(res.Peers, lag, res.TipAgeSeconds)
	res.Version = config.Version.String()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(health_http_code(res.Status))
	json.NewEncoder(w).Encode(res)
}
