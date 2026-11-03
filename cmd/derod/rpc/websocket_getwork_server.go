package rpc

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/lesismal/llib/std/crypto/tls"
	"github.com/lesismal/nbio/nbhttp"
	"github.com/lesismal/nbio/nbhttp/websocket"
)

import "github.com/lesismal/nbio"
import "github.com/lesismal/nbio/logging"

import "net"
import "bytes"
import "encoding/hex"
import "encoding/json"
import "runtime"
import "strings"
import "math/big"
import "crypto/ecdsa"
import "crypto/elliptic"

import "sync/atomic"
import "crypto/rand"
import "crypto/x509"
import "encoding/pem"

import "github.com/deroproject/derohe/globals"
import "github.com/deroproject/derohe/metrics"
import "github.com/deroproject/derohe/config"
import "github.com/deroproject/derohe/rpc"
import "github.com/deroproject/derohe/block"
import "github.com/deroproject/graviton"
import "github.com/go-logr/logr"

// this file implements the non-blocking job streamer
// only job is to stream jobs to thousands of workers, if any is successful,accept and report back

import "sync"

var memPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 16*1024)
	},
}

var logger_getwork logr.Logger
var (
	svr   *nbhttp.Server
	print = flag.Bool("print", false, "stdout output of echoed data")
)

type user_session struct {
	blocks        uint64
	miniblocks    uint64
	rejected      uint64
	lasterr       string
	address       rpc.Address
	valid_address bool
	address_sum   [32]byte
	checked_topo  int64     // topoheight of the last failed registration lookup; -1 = never looked up (r19)
	since         time.Time // connect time, for the disconnect log line (r20)
	remote        string
	send_mu       sync.Mutex  // r23: orders job writes to this miner (deliver_job)
	sent_seq      uint64      // r23: number of the newest job written to this miner (under send_mu)
	limit_key     string      // r23: getwork_guard key (IPv4 address / IPv6 /64)
	loopback      bool        // r23: loopback sessions are never limited
	guard         share_guard // r23: run of bad shares (getwork_guard.go)
	slot_once     sync.Once   // r23: release_slot runs once
}

var client_list_mutex sync.Mutex
var client_list = map[*websocket.Conn]*user_session{}

var miners_count int

// this will track miniblock rate,
var mini_found_time []int64 // this array contains a epoch timestamp in int64
var rate_lock sync.Mutex

// this function will return wrong result if too wide time glitches happen to system clock
func Counter(seconds int64) (r int) { // we need atleast 1 mini to find a rate
	rate_lock.Lock()
	defer rate_lock.Unlock()
	length := len(mini_found_time)
	if length > 0 {
		start_point := time.Now().Unix() - seconds
		i := sort.Search(length, func(i int) bool { return mini_found_time[i] >= start_point })
		if i < len(mini_found_time) {
			r = length - i
		}
	}
	return // return 0
}

func cleanup() {
	rate_lock.Lock()
	defer rate_lock.Unlock()
	length := len(mini_found_time)
	if length > 0 {
		start_point := time.Now().Unix() - 30*24*3600 // only keep data of last 30 days
		i := sort.Search(length, func(i int) bool { return mini_found_time[i] >= start_point })
		if i > 1000 && i < length {
			mini_found_time = append(mini_found_time[:0], mini_found_time[i:]...) // renew the array
		}
	}
}

// this will calcuate amount of hashrate based on the number of minis
// note this calculation is very crude
// note it will always be lagging, since NW conditions are quite dynamic
// this is  used to roughly estimate your hash rate on this integrator of all miners
// note this is a moving avg
func HashrateEstimatePercent(timeframe int64) float64 {
	return hashrate_estimate_percent(Counter(timeframe), timeframe, int64(time.Since(globals.StartTime).Seconds()))
}

// hashrate_estimate_percent: our share of the network's miniblocks in the window, as a percentage. The window is
// clipped to the uptime, because a 7-day window 30 minutes after a restart divided 30 minutes of finds by 7 days.
// 10 miniblocks per BLOCK_TIME (9 normal + 1 final) are paid; counting finals too keeps the share honest.
func hashrate_estimate_percent(found int, timeframe, uptime int64) float64 {
	if uptime < timeframe {
		timeframe = uptime
	}
	if timeframe <= 0 {
		return 0
	}
	return float64(found*100) / (float64(timeframe*10) / float64(config.BLOCK_TIME))
}

// note this will be be 0, if you have less than 1/48000 hash power
func HashrateEstimatePercent_1hr() float64 {
	return HashrateEstimatePercent(3600)
}

// note result will be 0, if you have  less than 1/2000 hash power
func HashrateEstimatePercent_1day() float64 {
	return HashrateEstimatePercent(24 * 3600)
}

// note this will be 0, if you have less than 1/(48000*7)
func HashrateEstimatePercent_7day() float64 {
	return HashrateEstimatePercent(7 * 24 * 3600)
}

func CountMiners() int {
	defer cleanup()
	client_list_mutex.Lock()
	defer client_list_mutex.Unlock()
	miners_count = len(client_list)
	return miners_count
}

var CountMinisAccepted int64 // total accepted which passed Powtest, chain may still ignore them
var CountMinisRejected int64 // total rejected // note we are only counting rejected as those which didnot pass Pow test
var CountBlocks int64        //  total blocks found as integrator, note that block can still be a orphan
// total = CountAccepted + CountRejected + CountBlocks(they may be orphan or may not get rewarded)

// template_refresh_due_ms is when a job built from a fresh template must be sent again (0 = none).
// Create_new_block_template_mining serves a cached template for 100 ms (blockchain/miner_block.go:397).
// A send triggered by a new miniblock inside that window therefore carries a template from before the
// miniblock arrived. When that miniblock is the 9th normal one, miners keep mining NORMAL work that can
// no longer be paid, until the 500 ms timer fires. The follow-up send closes that window at cache expiry.
var template_refresh_due_ms int64

// refresh_due returns when to resend for a template made at template_ms by a send started at trigger_ms,
// or 0 when the template is newer than the send. The cache expires once now > template_ms+100. A template stamped in
// the trigger's own millisecond may still be the cached one from before the miniblock landed; one spare resend is
// cheaper than mining dead work until the 500 ms timer (Round 17 verifier).
func refresh_due(template_ms, trigger_ms int64) int64 {
	if template_ms <= trigger_ms {
		return template_ms + 101
	}
	return 0
}

func SendJob() { send_job(globals.Time().UTC().UnixMilli()) }

// getwork_job_template_age: how old the template of each sent job is (now - its timestamp). Mostly 0; up to 100 ms when
// the template cache answered (blockchain/miner_block.go), which is the stale-template window refresh_due closes (r23).
var getwork_job_template_age = metrics.Set.NewHistogram("getwork_job_template_age_seconds")

// getwork_template_errors_total: sends that found no template (r23). Right after a block is added the template can fail
// for a moment; the old loop then waited up to 500 ms for its periodic resend while the miner hashed the finished height.
var getwork_template_errors = metrics.Set.NewCounter("getwork_template_errors_total")

// getwork_send_job_seconds: template fetch plus fan-out start of one job, i.e. derod's part of time-to-new-job (r23).
var getwork_send_job_seconds = metrics.Set.NewHistogram("getwork_send_job_seconds")

// send_job sends one job to every miner. trigger_ms is when the state this job answers was observed (0: no state
// change, nothing to refresh for); a template stamped at or before it may be the cached one from before the change.
// It reports false when the job could not be current: no template, or a template for a height the chain already has.
func send_job(trigger_ms int64) bool { return send_job_to(trigger_ms, nil) }

// template_is_current: a template extends the chain only if it is for the height after the chain's top.
func template_is_current(template_height, chain_height int64) bool {
	return template_height > chain_height
}

// getwork_stale_height_jobs_total: jobs built while a block was half added (r23). Add_Complete_Block writes the topo
// record (Get_Height moves) before it updates chain.Tips (blockchain/blockchain.go), so a template built in between
// is for the finished height. Loopback measurement (2026-10-30): the pre-r23 loop sent such a job first after 44 of 53
// blocks, and in about half of them sent nothing better until its 500 ms resend.
var getwork_stale_height_jobs = metrics.Set.NewCounter("getwork_stale_height_jobs_total")

// stale_counted: only broadcasts count as stale-height jobs; a connecting miner's first job (targets != nil) would
// inflate the live check stale_height_jobs / blocks with reconnects (r23 merge).
func stale_counted(current bool, targets []job_target) bool { return !current && targets == nil }

// send_job_to sends one job to targets, or to every miner when targets is nil.
func send_job_to(trigger_ms int64, targets []job_target) (current bool) {

	defer globals.Recover(1)

	t0 := time.Now()
	defer func() { getwork_send_job_seconds.Update(time.Since(t0).Seconds()) }()

	// get a block template, and then we will fill the address here as optimization
	// r23 (rpcws): fetched under sendjob_mu and numbered, so a miner never ends on an older job than one it already got
	var bl block.Block
	var mbl_main block.MiniBlock
	var err error
	seq, ok := next_job_seq(func() bool {
		bl, mbl_main, _, _, err = chain.Create_new_block_template_mining(chain.IntegratorAddress())
		return err == nil
	})
	if !ok {
		getwork_template_errors.Inc()
		return false
	}
	NoteTemplate(&bl) // r24 (verify-txpool): the pool cap never evicts a tx this job's template carries
	current = template_is_current(int64(bl.Height), chain.Get_Height())
	if stale_counted(current, targets) {
		getwork_stale_height_jobs.Inc() // still sent (never starve a miner on a wrong guess); the dispatcher retries
	}
	if current { // r23c payouts: dead normal work after the 9th miniblock (getwork_flip.go)
		note_flip(chain.MiniBlocks, &bl, mbl_main.Final, trigger_ms, globals.Time().UTC().UnixMilli()) // r24: + trigger (L9)
	}
	if age := globals.Time().UTC().UnixMilli() - int64(bl.Timestamp); age >= 0 {
		getwork_job_template_age.Update(float64(age) / 1000)
	}
	if due := refresh_due(int64(bl.Timestamp), trigger_ms); due != 0 {
		atomic.CompareAndSwapInt64(&template_refresh_due_ms, 0, due) // the dispatch loop clears it when it fires
	}

	prev_hash := ""
	for i := range bl.Tips {
		prev_hash = prev_hash + bl.Tips[i].String()
	}

	diff := chain.Get_Difficulty_At_Tips(bl.Tips)

	if mbl_main.HighDiff {
		diff.Mul(diff, new(big.Int).SetUint64(config.MINIBLOCK_HIGHDIFF))
	}
	// r18: everything that is the same for every miner is computed once per job instead of once per client goroutine
	// (JobID Sprintf, diff.String(), diff.Uint64()); job_message fills in the per-miner fields.
	var base rpc.GetBlockTemplate_Result
	base.JobID = fmt.Sprintf("%d.%d.%s", bl.Timestamp, 0, "notified")
	base.Height = bl.Height
	base.Prev_Hash = prev_hash
	base.Difficultyuint64 = diff.Uint64()
	base.Difficulty = diff.String()

	// r19: registration only changes when the chain moves, so an unregistered session is looked up again only at a
	// new topoheight, and sessions sharing an address share one lookup per job. Before, every push to every
	// unregistered session re-read the balance tree from disk: 1000 such connections cost 85% of a 1.7-core load.
	if targets == nil {
		targets = job_targets()
	}
	topo := int64(-1)
	for i := range targets {
		if !targets[i].valid { // registered miners (the usual case) cost no topoheight read at all
			topo = chain.Load_TOPO_HEIGHT()
			break
		}
	}
	reg := new_reg_lookups(func(a [32]byte) bool { return chain.IsAddressHashValid(false, a) })
	dispatch_targets(targets, base, mbl_main, reg, topo, seq, nil)
	return current
}

// dispatch_targets writes job seq to every target, one goroutine per miner (an nbio write never blocks: it buffers,
// and the write deadline or the buffer cap closes a miner that does not read). done, when not nil, is called once per
// target after its write (benchmarks).
func dispatch_targets(targets []job_target, base rpc.GetBlockTemplate_Result, mbl_main block.MiniBlock, reg *reg_lookups, topo int64, seq uint64, done func()) {
	jf := new_job_frame(base) // r21: shared fields encoded once per job (job_frame.go)

	for _, rt := range targets {

		go func(t job_target) {
			defer globals.Recover(2)
			if done != nil {
				defer done()
			}

			params := base
			mbl := mbl_main

			if !mbl.Final { //write miners address only if possible
				copy(mbl.KeyHash[:], t.address_sum[:])
			}

			fill_nonce(&mbl) // give each user different work

			registered := t.registered(reg, topo)
			var msg []byte
			if jf != nil {
				msg = jf.frame(&mbl, t.blocks, t.miniblocks, t.rejected, registered)
			} else {
				if !registered {
					params.LastError = job_unregistered_error
				}
				msg = job_message(params, &mbl, t.blocks, t.miniblocks, t.rejected)
			}
			if sent, err := deliver_job(t.sess, t.conn, seq, msg); err != nil {
				getwork_job_write_errors.Inc()
			} else if sent {
				getwork_jobs_sent.Inc()
			}

		}(rt)

	}
}

// job_target is one miner's share of a job: the connection plus a copy of its session fields taken under
// client_list_mutex. The per-miner goroutines used to read blocks/miniblocks/rejected and write valid_address through
// the shared *user_session with no lock while OnMessage updated them under it, which is a data race (r19).
type job_target struct {
	conn                         *websocket.Conn
	sess                         *user_session
	address_sum                  [32]byte
	blocks, miniblocks, rejected uint64
	valid                        bool  // registration already confirmed
	checked_topo                 int64 // topoheight of the last failed lookup, -1 = none
}

// needs_registration_check: a confirmed address is never looked up again (as before); an unconfirmed one only when the
// topoheight differs from the one its last failed lookup ran at, since IsAddressHashValid reads the state at
// Load_TOPO_HEIGHT()-25 and that cannot change while the topoheight does not.
func needs_registration_check(valid bool, checked_topo, topo int64) bool {
	return !valid && checked_topo != topo
}

// job_targets snapshots every session under the lock and releases it before any lookup or network write.
func job_targets() []job_target {
	client_list_mutex.Lock()
	defer client_list_mutex.Unlock()
	targets := make([]job_target, 0, len(client_list))
	for k, v := range client_list {
		targets = append(targets, job_target{conn: k, sess: v, address_sum: v.address_sum, blocks: v.blocks,
			miniblocks: v.miniblocks, rejected: v.rejected, valid: v.valid_address, checked_topo: v.checked_topo})
	}
	return targets
}

// job_target_for snapshots one session, false when it is not (or no longer) registered.
func job_target_for(c *websocket.Conn) (job_target, bool) {
	client_list_mutex.Lock()
	defer client_list_mutex.Unlock()
	v, ok := client_list[c]
	if !ok {
		return job_target{}, false
	}
	return job_target{conn: c, sess: v, address_sum: v.address_sum, blocks: v.blocks, miniblocks: v.miniblocks,
		rejected: v.rejected, valid: v.valid_address, checked_topo: v.checked_topo}, true
}

// registered answers whether this target's address may mine, doing the lookup only when it is due and recording the
// result in the session under the lock.
func (t job_target) registered(reg *reg_lookups, topo int64) bool {
	if !needs_registration_check(t.valid, t.checked_topo, topo) {
		return t.valid
	}
	ok := reg.registered(t.address_sum)
	client_list_mutex.Lock()
	if ok {
		t.sess.valid_address = true
	} else {
		t.sess.checked_topo = topo
	}
	client_list_mutex.Unlock()
	return ok
}

// reg_lookups runs at most one registration lookup per address for one job, however many sessions share it.
type reg_lookups struct {
	mu     sync.Mutex
	m      map[[32]byte]*reg_entry
	lookup func([32]byte) bool
}

type reg_entry struct {
	once sync.Once
	ok   bool
}

func new_reg_lookups(lookup func([32]byte) bool) *reg_lookups {
	return &reg_lookups{m: map[[32]byte]*reg_entry{}, lookup: lookup}
}

func (r *reg_lookups) registered(a [32]byte) bool {
	r.mu.Lock()
	e := r.m[a]
	if e == nil {
		e = &reg_entry{}
		r.m[a] = e
	}
	r.mu.Unlock()
	e.once.Do(func() { e.ok = r.lookup(a) })
	return e.ok
}

// verify_slot bounds how many submitted shares derod verifies at once. Verification (PoW plus insert) used to run
// while holding client_list_mutex, which serialised it but also stalled every SendJob behind it: a flood of bad
// shares on a public getwork port delayed the jobs of honest miners. One slot keeps the old CPU bound (r19).
var verify_slot = make(chan struct{}, 1)

func verify_share(f func()) {
	verify_slot <- struct{}{}
	defer func() { <-verify_slot }()
	f()
}

// record_share updates the session and global counters for one verified share.
func record_share(sess *user_session, accepted bool, err error, mini bool) {
	client_list_mutex.Lock()
	defer client_list_mutex.Unlock()
	if accepted {
		if mini {
			sess.miniblocks++
			atomic.AddInt64(&CountMinisAccepted, 1)
		} else {
			sess.blocks++
			atomic.AddInt64(&CountBlocks, 1)
		}
		// a final miniblock is one of the block's 10 paid shares too; leaving it out undercounted the estimate
		rate_lock.Lock()
		mini_found_time = append(mini_found_time, time.Now().Unix())
		rate_lock.Unlock()
		note_share_accepted(time.Now())
	}
	if !accepted || err != nil {
		sess.rejected++
		atomic.AddInt64(&CountMinisRejected, 1)
	}
}

// job_message is the JSON text frame one miner receives: params (the shared job fields plus this miner's LastError)
// with this miner's blob and counters, encoded by json.Encoder exactly as before (HTML escaping on, trailing '\n').
// hex.EncodeToString produces the same lowercase hex as the old fmt.Sprintf("%x", ...) without fmt's reflection.
func job_message(params rpc.GetBlockTemplate_Result, mbl *block.MiniBlock, blocks, miniblocks, rejected uint64) []byte {
	var buf bytes.Buffer
	params.Blockhashing_blob = hex.EncodeToString(mbl.Serialize())
	params.Blocks = blocks
	params.MiniBlocks = miniblocks
	params.Rejected = rejected
	json.NewEncoder(&buf).Encode(params)
	return buf.Bytes()
}

func newUpgrader() *websocket.Upgrader {
	u := websocket.NewUpgrader()
	u.ReadLimit = GETWORK_READ_LIMIT // a share is ~200 bytes of JSON; nbio's default of 0 meant unlimited (bind_policy.go)

	u.OnMessage(func(c *websocket.Conn, messageType websocket.MessageType, data []byte) {
		// echo
		//c.WriteMessage(messageType, data)

		if messageType != websocket.TextMessage {
			return
		}

		sess := c.Session().(*user_session)
		if getwork_session_refused(sess, time.Now()) { // r23: closed for bad shares, or its key is banned
			if !sess.guard.is_closed() {
				c.Close()
			}
			return
		}

		var p rpc.SubmitBlock_Params

		if err := json.Unmarshal(data, &p); err != nil {

		}

		mbl_block_data_bytes, err := hex.DecodeString(p.MiniBlockhashing_blob)
		if err != nil {
			//logger.Info("Submitting block could not be decoded")
			client_list_mutex.Lock()
			sess.lasterr = fmt.Sprintf("Submitted block could not be decoded. err: %s", err)
			client_list_mutex.Unlock()
			getwork_note_share(c, sess, false, err_share_undecodable)
			return
		}

		var tstamp, extra uint64
		fmt.Sscanf(p.JobID, "%d.%d", &tstamp, &extra)

		var share_ok bool
		var share_err error
		verify_share_from(sess.loopback, func() { // r23: remote shares queue behind one gate (getwork_guard.go)
			_, blid, sresult, err := chain.Accept_new_block(tstamp, mbl_block_data_bytes)
			share_ok, share_err = sresult, err
			if sresult {
				built := ""
				if !blid.IsZero() {
					built = blid.String()
				}
				record_submission_built(mbl_block_data_bytes, built) // its fate is resolved once its height is stable (mining_outcome.go)
			}
			record_share(sess, sresult, err, blid.IsZero())
		})
		getwork_note_share(c, sess, share_ok, share_err)

	})
	u.OnClose(func(c *websocket.Conn, err error) {
		sess, ev, left := getwork_unregister(c)
		if s, ok := c.Session().(*user_session); ok && s != nil {
			s.release_slot() // r23: frees its per-IP slot once, registered or not (getwork_guard.go)
		}
		if sess != nil && ev != "" {
			client_list_mutex.Lock() // the session counters are written under this lock (record_share)
			minis, blocks, rejected := sess.miniblocks, sess.blocks, sess.rejected
			client_list_mutex.Unlock()
			reason := ""
			if err != nil {
				reason = err.Error()
			}
			log_presence(ev, "remote", sess.remote, "connected_for", time.Since(sess.since).Round(time.Second).String(),
				"miniblocks", minis, "blocks", blocks, "rejected", rejected, "miners", left, "err", reason)
		}
	})

	return u
}

func onWebsocket(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/ws/") {
		http.NotFound(w, r)
		return
	}
	address := strings.TrimPrefix(r.URL.Path, "/ws/")

	limit_key, loopback, admitted := getwork_admit(w, r.RemoteAddr) // r23: per-IP cap and bad-share bans (getwork_guard.go)
	if !admitted {
		return
	}
	registered := false
	defer func() {
		if !registered && !loopback {
			getwork_conn_limit.release(limit_key)
		}
	}()

	addr, err := globals.ParseValidateAddress(address)
	if err != nil {
		fmt.Fprintf(w, "err: %s\n", err)
		return
	}
	addr_raw := addr.PublicKey.EncodeCompressed()

	upgrader := newUpgrader()
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		//panic(err)
		return
	}
	wsConn := conn.(*websocket.Conn)

	session := user_session{address: *addr, address_sum: graviton.Sum(addr_raw), checked_topo: -1, since: time.Now(), remote: r.RemoteAddr,
		limit_key: limit_key, loopback: loopback}
	wsConn.SetSession(&session)
	registered = true // the slot is now released by OnClose

	if ev, n := getwork_register(wsConn, &session); ev != "" {
		log_presence(ev, "remote", r.RemoteAddr, "miners", n)
	}
	// r23: a (re)connected miner gets work now instead of at the next job; only this miner, so a connect flood on a
	// public getwork port cannot make derod resend every honest miner's job (a cached template costs no build)
	if t, ok := job_target_for(wsConn); ok {
		getwork_first_jobs.Inc()
		go send_job_to(0, []job_target{t})
	}

}

func Getwork_server() {

	var err error

	logger_getwork = globals.Logger.WithName("GETWORK")
	configure_getwork_guard(os.Getenv) // r23: DERO_GETWORK_MAX_PER_IP (getwork_guard.go)

	logging.SetLevel(logging.LevelNone) //LevelDebug)//LevelNone)

	tlsConfig := getwork_server_tls_config() // r23: TLS 1.2+ and AEAD-only suites (getwork_tls.go)

	mux := &http.ServeMux{}
	mux.HandleFunc("/", onWebsocket) // handle everything

	default_address := fmt.Sprintf("0.0.0.0:%d", globals.Config.GETWORK_Default_Port)

	if _, ok := globals.Arguments["--getwork-bind"]; ok && globals.Arguments["--getwork-bind"] != nil {
		addr, err := net.ResolveTCPAddr("tcp", globals.Arguments["--getwork-bind"].(string))
		if err != nil {
			logger_getwork.Error(err, "--getwork-bind address is invalid")
			return
		} else {
			if addr.Port == 0 {
				logger_getwork.Info("GETWORK server is disabled, No ports will be opened for miners to get work")
				return
			} else {
				default_address = addr.String()
			}
		}
	}

	logger_getwork.Info("GETWORK will listen", "address", default_address)
	if !bind_is_loopback(default_address) {
		logger_getwork.Info("WARNING: getwork is reachable from the network without authentication; every submitted miniblock costs one PoW verification. Use --getwork-bind=127.0.0.1:10100 unless remote miners need it", "address", default_address)
	}

	svr = nbhttp.NewServer(nbhttp.Config{
		Name:                    "GETWORK",
		Network:                 "tcp",
		AddrsTLS:                []string{default_address},
		TLSConfig:               tlsConfig,
		Handler:                 mux,
		MaxLoad:                 10 * 1024,
		MaxWriteBufferSize:      32 * 1024,
		ReleaseWebsocketPayload: true,
		KeepaliveTime:           240 * time.Hour, // we expects all miners to find a block every 10 days,
		NPoller:                 runtime.NumCPU(),
	})

	svr.OnReadBufferAlloc(func(c *nbio.Conn) []byte {
		return memPool.Get().([]byte)
	})
	svr.OnReadBufferFree(func(c *nbio.Conn, b []byte) {
		memPool.Put(b)
	})

	//globals.Cron.AddFunc("@every 2s", SendJob) // if daemon restart automaticaly send job
	// r23: one event-driven dispatcher (job_dispatch.go) instead of a per-miniblock SendJob plus a 10 ms poll loop
	keepalive := job_keepalive_ms(os.Getenv("JOB_SEND_TIME_DELAY"))
	sleeptime := time.Duration(keepalive) * time.Millisecond // the resend interval of an UNCHANGED job; changes go out at once
	logger_getwork.Info("Job will be dispatched every", "time", sleeptime)
	go func() { // a block addition (also at the same height) must reach the miners at once, not at the next poll
		for {
			chain.RPC_NotifyNewBlock.L.Lock()
			chain.RPC_NotifyNewBlock.Wait()
			chain.RPC_NotifyNewBlock.L.Unlock()
			note_job_event()
		}
	}()
	go run_job_dispatcher(&dispatch_core{keepalive_ms: keepalive, due: &template_refresh_due_ms}, JOB_POLL.Milliseconds(),
		func() bool { return atomic.LoadInt64(&getwork_session_count) > 0 },
		func() dispatch_state {
			return dispatch_state{height: chain.Get_Height(), minis: chain.MiniBlocks.Count(), events: atomic.LoadUint64(&job_events)}
		},
		func() int64 { return globals.Time().UTC().UnixMilli() },
		send_job, job_kick, nil)

	if after := miner_absent_warn_after(os.Getenv("DERO_MINER_ABSENT_WARN_MIN")); after > 0 { // r23b (getwork_absence.go)
		go run_absence_watch(after, time.NewTicker(time.Minute).C, func(absent time.Duration, since time.Time) {
			logger_getwork.Info("WARNING: no miner connected, this node is not earning", "absent_for", absent.Round(time.Second).String(),
				"since", since.Format(time.RFC3339), "metric", "getwork_miner_absent_seconds")
		})
	}

	if err = svr.Start(); err != nil {
		logger_getwork.Error(err, "nbio.Start failed.")
		return
	}
	logger.Info("GETWORK/Websocket server started")
	svr.Wait()
	defer svr.Stop()

}

// generate default tls cert to encrypt everything
// NOTE: this does NOT protect from individual active man-in-the-middle attacks
// getwork_cert_serial is a random positive 127-bit certificate serial (as p2p's random_cert_serial). The certificate is
// self-signed and never verified by miners (InsecureSkipVerify); the serial only must not identify the node.
func getwork_cert_serial() *big.Int {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[0] &= 0x7f
	b[15] |= 1 // never zero
	return new(big.Int).SetBytes(b[:])
}

func generate_random_tls_cert() tls.Certificate {

	/* RSA can do only 500 exchange per second, we need to be faster
	     * reference https://github.com/golang/go/issues/20058
	    key, err := rsa.GenerateKey(rand.Reader, 512) // current using minimum size
	if err != nil {
	    log.Fatal("Private key cannot be created.", err.Error())
	}

	// Generate a pem block with the private key
	keyPem := pem.EncodeToMemory(&pem.Block{
	    Type:  "RSA PRIVATE KEY",
	    Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	*/
	// EC256 does roughly 20000 exchanges per second
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		logger.Error(err, "Unable to marshal ECDSA private key")
		panic(err)
	}
	// Generate a pem block with the private key
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})

	tml := x509.Certificate{
		SerialNumber: getwork_cert_serial(), // r23b: was UnixNano, which told every miner when derod started

		// TODO do we need to add more parameters to make our certificate more authentic
		// and thwart traffic identification as a mass scale

		// you can add any attr that you need
		NotBefore: time.Now().AddDate(0, -1, 0),
		NotAfter:  time.Now().AddDate(1, 0, 0),
		// you have to generate a different serial number each execution
		/*
		   Subject: pkix.Name{
		       CommonName:   "New Name",
		       Organization: []string{"New Org."},
		   },
		   BasicConstraintsValid: true,   // even basic constraints are not required
		*/
	}
	cert, err := x509.CreateCertificate(rand.Reader, &tml, &tml, &key.PublicKey, key)
	if err != nil {
		logger.Error(err, "Certificate cannot be created.")
		panic(err)
	}

	// Generate a pem block with the certificate
	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	tlsCert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		logger.Error(err, "Certificate cannot be loaded.")
		panic(err)
	}
	return tlsCert
}
