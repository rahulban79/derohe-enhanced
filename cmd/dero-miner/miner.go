// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package main

import "io"
import "os"
import "fmt"
import "time"
import "net"
import "net/url"
import "encoding/json"
import "crypto/rand"
import "crypto/tls"
import "sync"
import "runtime"
import "math"
import "math/big"
import "path/filepath"
import "encoding/binary"
import "os/signal"
import "syscall"
import "sync/atomic"
import "strings"
import "strconv"

import "github.com/go-logr/logr"

import "github.com/deroproject/derohe/config"
import "github.com/deroproject/derohe/globals"

//import "github.com/deroproject/derohe/cryptography/crypto"
import "github.com/deroproject/derohe/block"
import "github.com/deroproject/derohe/rpc"

import "github.com/chzyer/readline"
import "github.com/docopt/docopt-go"

import "github.com/deroproject/derohe/astrobwt/astrobwt_fast"
import "github.com/deroproject/derohe/astrobwt/astrobwtv3"
import "github.com/deroproject/derohe/cmd/dero-miner/astropair"

import "github.com/gorilla/websocket"
import "github.com/deroproject/graviton"

var mutex sync.RWMutex
var job rpc.GetBlockTemplate_Result
var job_counter int64
var maxdelay int = 10000
var threads int
var cpu_max int = 90 // cap per-thread CPU duty cycle (percent) to limit heat/power; 100 = full speed
var iterations int = 100
var max_pow_size int = 819200 //astrobwt.MAX_LENGTH
var wallet_address string
var daemon_rpc_address string

var counter uint64
var hash_rate uint64
var Difficulty uint64
var our_height int64

var block_counter uint64
var mini_block_counter uint64
var rejected uint64

var gpu_max int = 90 // cap GPU duty cycle (percent) to limit heat/power; parity with --cpu-max
// per-source miniblock shares found+submitted (local, exact attribution of who did the work)
var cpu_minis uint64
var gpu_minis uint64

// submit-path latency instrumentation (observability for the reward-critical share submit).
// submit_ns_total accumulates lock+serialize+write nanoseconds; submit_count counts submits.
var submit_count uint64
var submit_ns_total uint64
var submit_ns_max uint64
var logger logr.Logger

var command_line string = `dero-miner
DERO CPU Miner for AstroBWT.
ONE CPU, ONE VOTE.
http://wiki.dero.io

Usage:
  dero-miner  --wallet-address=<wallet_address> [--daemon-rpc-address=<minernode1.dero.live:10100>] [--mining-threads=<threads>] [--cpu-max=<90>] [--gpu=<path>] [--gpu-mode=<full>] [--gpu-max=<90>] [--node-rpc-address=<127.0.0.1:10102>] [--sort=<auto>] [--pair=<auto>] [--cpu-qos=<default>] [--metrics-bind=<127.0.0.1:10109>] [--phase-duty=<off>] [--supervised] [--testnet] [--debug]
  dero-miner --bench [--cpu-max=<90>] [--sort=<auto>] [--pair=<auto>] [--cpu-qos=<default>] [--mining-threads=<threads>] [--gpu-mode=<full>]
  dero-miner -h | --help
  dero-miner --version

Options:
  -h --help     Show this screen.
  --version     Show version.
  --bench  	    Run benchmark mode.
  --daemon-rpc-address=<127.0.0.1:10102>    Miner will connect to daemon RPC on this port (default minernode1.dero.live:10100).
  --wallet-address=<wallet_address>    This address is rewarded when a block is mined sucessfully.
  --mining-threads=<threads>         Number of CPU threads for mining [default: ` + fmt.Sprintf("%d", runtime.GOMAXPROCS(0)) + `]
  --cpu-max=<percent>    Cap per-thread CPU duty cycle to this percent (1-100) to limit heat/power; mining only, --bench always runs at full speed. auto or auto:<floor> = start at 90 and A/B-tune it live in 5-point steps (never above 100, never below the floor, default 50; every step logged) [default: 90]
  --sort=<auto|native|go|descriptor|sais>    Suffix sort: auto/native = the descriptor sort in C where built (darwin/arm64), else Go; go/descriptor = the Go port; all self-tested at start and sampled while mining; sais = built-in [default: auto]
  --pair=<auto|off>    Hash two nonces per CPU iteration with interleaved final SHA-256 (self-tested at start) [default: auto]
  --cpu-qos=<default|initiated|interactive>    macOS scheduler class for mining threads; interactive prefers P-cores [default: default]
  --gpu=<path>    Also mine on the Apple Metal GPU using the hash-server binary at <path> (e.g. gpu-miner-poc/gpu_hash_sais). Adds ~+15%% alongside the CPU; gated by a bit-exact self-test.
  --gpu-mode=<full|split>    full: the GPU hashes its own nonces end to end (gpu_hash_sais). split: the GPU computes stage 1 + the final SHA-256 into shared memory and every CPU thread only sorts staged texts (gpu_split_server next to --gpu); bit-exact self-test, falls back to full [default: full]
  --gpu-max=<percent>    Cap GPU duty cycle to this percent (1-100) to limit heat/power; split mode enforces it as a duty bucket since r22 (r21 ran ~5 points above it: 96 keeps the r21 rate); auto or auto:<floor> tunes it live like --cpu-max=auto [default: 90]
  --metrics-bind=<host:port>    Serve Prometheus /metrics and a live /dashboard on this address (off by default; loopback only unless ENABLE_PUBLIC_METRICS=1). Never exposes the wallet address.
  --phase-duty=<off|balanced|R:F>    Duty cap by block phase (phase_duty.go): a regular-phase hash earns 9x a final-phase one. R:F = regular R%%, final F%%; balanced = regular 100%%, final chosen so the mean stays at --cpu-max; not with --cpu-max/--gpu-max=auto [default: off]
  --supervised    Run under a supervisor (launchd, tools/launchd): the console's exit/quit/bye are ignored; stop with SIGTERM/SIGINT (launchctl). The miner already keeps reconnecting to the daemon.
  --node-rpc-address=<host:port>    derod JSON-RPC (not getwork) to read which accepted shares were PAID (DERO.GetMiningOutcome, read-only). Default: the loopback daemon's RPC port; off disables.

Example Mainnet: ./dero-miner-linux-amd64 --wallet-address dero1qy0ehnqjpr0wxqnknyc66du2fsxyktppkr8m8e6jvplp954klfjz2qqhmy4zf --daemon-rpc-address=minernode1.dero.live:10100
Example Testnet: ./dero-miner-linux-amd64 --wallet-address deto1qy0ehnqjpr0wxqnknyc66du2fsxyktppkr8m8e6jvplp954klfjz2qqdzcd8p --daemon-rpc-address=127.0.0.1:40402 
If daemon running on local machine no requirement of '--daemon-rpc-address' argument. 
`
var Exit_In_Progress = make(chan bool)

// supervised (--supervised, r23b): over the 72 h before 2026-10-30 19:10 the miner ran 31% of the time; all nine
// runs in the ledger ended "console exit", and the longest gap was 10.5 h. Under a supervisor the console's exit is
// ignored and the run ends only by a signal, which the run ledger records.
var supervised bool

// console_exit_allowed: may the console's exit/quit/bye stop this miner?
func console_exit_allowed(supervised bool) bool { return !supervised }

const supervised_exit_message = "--supervised: console exit ignored; stop the miner with Ctrl-C, SIGTERM or launchctl bootout"

// is_console_exit_word: the console's exit/quit/bye.
func is_console_exit_word(line string) bool {
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "bye", "exit", "quit":
		return true
	}
	return false
}

// console_exit handles a typed exit word: ignored (message, log) when supervised, else exit("console <word>").
// It reports whether exit was called. The console loop calls it for every exit word (TestConsoleLoopWiresExit).
func console_exit(line string, supervised bool, out io.Writer, exit func(reason string)) bool {
	w := strings.ToLower(strings.TrimSpace(line))
	if !console_exit_allowed(supervised) {
		fmt.Fprintln(out, supervised_exit_message)
		logger.Info("console exit ignored", "reason", "--supervised", "line", w)
		return false
	}
	logger.Info("miner exiting", "reason", "console "+w)
	exit("console " + w)
	return true
}

var exit_once sync.Once

// request_exit closes Exit_In_Progress exactly once. It was closed directly at three sites (the signal goroutine, the
// console's Ctrl-C and its exit/quit/bye), so a second SIGINT, or a SIGINT followed by "exit", panicked with "close of
// closed channel". derod has the same helper (cmd/derod/main.go request_exit).
func request_exit() { close_once(&exit_once, Exit_In_Progress) }

// miner_exit_signals: SIGHUP joins SIGINT and SIGTERM. A miner started in a terminal that was then closed (or an ssh
// session that dropped) died of SIGHUP's default action without a word in its log; it now logs why and exits cleanly.
// BUT only when SIGHUP was not already ignored at start: signal.Notify(SIGHUP) removes the SIG_IGN that `nohup`
// installs, so registering it unconditionally made `nohup dero-miner ... &` exit when its terminal closed (r20
// review, reproduced with a go1.26 test program). ignored is signal.Ignored, evaluated before any Notify call.
func miner_exit_signals(ignored func(os.Signal) bool) []os.Signal {
	sigs := []os.Signal{os.Interrupt, syscall.SIGTERM}
	if !ignored(syscall.SIGHUP) {
		sigs = append(sigs, syscall.SIGHUP)
	}
	return sigs
}

func close_once(once *sync.Once, ch chan bool) {
	once.Do(func() { close(ch) })
}

// exit_on_signal: SIGINT or SIGTERM requests exit and closes the console, so the blocked Readline returns io.EOF and
// main returns. Before, only os.Interrupt was caught and the console stayed blocked (a "kill -INT" did nothing
// visible; a second one panicked), and SIGTERM (launchd, kill) was not caught at all.
func exit_on_signal(sigs <-chan os.Signal, console io.Closer, request func()) {
	for sig := range sigs {
		fmt.Printf("received signal %s\n", sig)
		logger.Info("miner exiting", "reason", "signal "+sig.String()) // r20: a run's end was never in the log file
		finish_run("signal " + sig.String())                           // r21: and in the run ledger
		request()
		if console != nil {
			console.Close()
		}
	}
}

func main() {

	var err error

	globals.Arguments, err = docopt.Parse(command_line, nil, true, config.Version.String(), false)

	if err != nil {
		fmt.Printf("Error while parsing options err: %s\n", err)
		return
	}

	// We need to initialize readline first, so it changes stderr to ansi processor on windows

	l, err := readline.NewEx(&readline.Config{
		//Prompt:          "\033[92mDERO:\033[32m»\033[0m",
		Prompt:          "\033[92mDERO Miner:\033[32m>>>\033[0m ",
		HistoryFile:     filepath.Join(os.TempDir(), "dero_miner_readline.tmp"),
		AutoComplete:    completer,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",

		HistorySearchFold:   true,
		FuncFilterInputRune: filterInput,
	})
	if err != nil {
		panic(err)
	}
	defer l.Close()

	// parse arguments and setup logging , print basic information
	exename, _ := os.Executable()
	logfile := log_path(exename, os.Args[1:])
	f, err := open_rotating_log(logfile, MINER_LOG_MAX_BYTES, MINER_LOG_BACKUPS) // append + rotate: never truncate (r20)
	if err != nil {
		fmt.Printf("Error while opening log file err: %s filename %s\n", err, logfile)
		return
	}
	globals.InitializeLog(l.Stdout(), f)
	logger = globals.Logger.WithName("miner")
	if err := set_crash_output(logfile + ".crash"); err != nil {
		logger.Error(err, "fatal-error traces will reach the terminal only")
	}

	logger.Info("DERO Stargate HE AstroBWT miner : It is an alpha version, use it for testing/evaluations purpose only.")
	logger.Info("Copyright 2017-2021 DERO Project. All rights reserved.")
	logger.Info("", "OS", runtime.GOOS, "ARCH", runtime.GOARCH, "GOMAXPROCS", runtime.GOMAXPROCS(0))
	logger.Info("", "Version", config.Version.String())

	logger.V(1).Info("", "Arguments", globals.Arguments)

	globals.Initialize() // setup network and proxy

	logger.V(0).Info("", "MODE", globals.Config.Name)

	if globals.Arguments["--wallet-address"] != nil {
		addr, err := globals.ParseValidateAddress(globals.Arguments["--wallet-address"].(string))
		if err != nil {
			logger.Error(err, "Wallet address is invalid.")
			return
		}
		wallet_address = addr.String()
		set_own_key_hash(graviton.Sum(addr.PublicKey.EncodeCompressed())) // jobs must pay this key (job_guard.go)
	}

	submit_bucket = new_submit_limiter(globals.Arguments["--testnet"].(bool), os.Getenv("DERO_MINER_SUBMIT_RATE")) // r22 (job_guard.go)
	if !globals.Arguments["--testnet"].(bool) {
		daemon_rpc_address = "minernode1.dero.live:10100"
	} else {
		daemon_rpc_address = "127.0.0.1:10100"
	}

	if globals.Arguments["--daemon-rpc-address"] != nil {
		daemon_rpc_address = globals.Arguments["--daemon-rpc-address"].(string)
	}

	threads = runtime.GOMAXPROCS(0)
	if globals.Arguments["--mining-threads"] != nil {
		if s, err := strconv.Atoi(globals.Arguments["--mining-threads"].(string)); err == nil {
			threads = s
		} else {
			logger.Error(err, "Mining threads argument cannot be parsed.")
		}

		if threads > runtime.GOMAXPROCS(0) {
			logger.Info("Mining threads is more than available CPUs. This is NOT optimal", "thread_count", threads, "max_possible", runtime.GOMAXPROCS(0))
		}
	}

	// r22: a percent, or auto / auto:<floor> (the duty tuner, dutytune.go)
	var cpu_auto, gpu_auto bool
	var cpu_floor, gpu_floor int
	if globals.Arguments["--cpu-max"] != nil {
		var err error
		if cpu_max, cpu_auto, cpu_floor, err = parse_duty_flag(globals.Arguments["--cpu-max"].(string), 90); err != nil {
			logger.Error(err, "cpu-max argument cannot be parsed, using default 90")
		}
	}
	cpu_max = set_cpu_duty(cpu_max)
	logger.Info(cpu_max_message(globals.Arguments["--bench"] == true, cpu_max))

	if globals.Arguments["--gpu-max"] != nil {
		var err error
		if gpu_max, gpu_auto, gpu_floor, err = parse_duty_flag(globals.Arguments["--gpu-max"].(string), 90); err != nil {
			logger.Error(err, "gpu-max argument cannot be parsed, using default 90")
		}
	}
	gpu_max = set_gpu_duty(gpu_max)

	if v, _ := globals.Arguments["--phase-duty"].(string); v != "" { // r23b (phase_duty.go)
		c, err := parse_phase_duty(v)
		switch {
		case err != nil:
			logger.Error(err, "phase-duty argument cannot be parsed, phase duty off")
		case c.on && (cpu_auto || gpu_auto):
			logger.Error(nil, "--phase-duty is not combined with --cpu-max=auto / --gpu-max=auto, phase duty off")
		case c.on:
			set_phase_duty(c)
			logger.Info("phase duty", "regular", c.regular, "final", c.final, "balanced", c.balanced, "cpu_max", cpu_max, "gpu_max", gpu_max)
		}
	}
	supervised = globals.Arguments["--supervised"] == true

	sort_mode := "auto"
	if globals.Arguments["--sort"] != nil {
		sort_mode = globals.Arguments["--sort"].(string)
	}
	merge := apply_merge_variant(os.Getenv)                                           // r30 L-C2 (default off)
	logger.Info("suffix sort", "using", install_fast_sort(sort_mode), "merge", merge) // S4b reads "using"
	pair_mode := "auto"
	if globals.Arguments["--pair"] != nil {
		pair_mode = globals.Arguments["--pair"].(string)
	}
	logger.Info("paired hashing", "state", install_pair_hash(pair_mode))
	if globals.Arguments["--cpu-qos"] != nil {
		switch globals.Arguments["--cpu-qos"].(string) {
		case "initiated":
			cpu_qos = 1
		case "interactive":
			cpu_qos = 2
		}
	}

	if globals.Arguments["--bench"].(bool) {

		// --gpu-mode=split: the CPU side of split mode only (splitbench.go); the GPU is never started under --bench
		if split_bench_requested(globals.Arguments) {
			if !split_bench(threads, 1000) {
				os.Exit(1)
			}
			os.Exit(0)
		}

		var wg sync.WaitGroup

		fmt.Printf("sort: %s · %s · cpu-qos: %d\n", fast_sort_status(), pair_status(), cpu_qos)
		// H/cpu-s sits before the wall H/s so parsers that read the last column (harness bench_rate) keep working
		fmt.Printf("%20s %20s %20s %20s %20s %20s \n", "Threads", "Total Time", "Total Iterations", "Time/PoW ", "Hash/CPU-Sec", "Hash Rate/Sec")
		iterations = 1000
		for bench := 1; bench <= threads; bench++ {
			processor = 0
			cpu0 := process_cpu_time()
			now := time.Now()
			for i := 0; i < bench; i++ {
				wg.Add(1)
				go random_execution(&wg, iterations)
			}
			wg.Wait()
			duration := time.Now().Sub(now)
			cpu := process_cpu_time() - cpu0

			fmt.Printf("%20s %20s %20s %20s %20s %20s \n", fmt.Sprintf("%d", bench), fmt.Sprintf("%s", duration), fmt.Sprintf("%d", bench*iterations),
				fmt.Sprintf("%s", duration/time.Duration(bench*iterations)), cpu_rate_string(bench*iterations, cpu),
				fmt.Sprintf("%.1f", float32(time.Second)/(float32(duration/time.Duration(bench*iterations)))))

		}

		os.Exit(0)
	}

	logger.Info(fmt.Sprintf("System will mine to \"%s\" with %d threads. Good Luck!!", wallet_address, threads))

	// r21: one JSON line per run (runledger.go); a checkpoint left by a run that never reached its exit path is
	// recorded first, as unclean
	if rl, recovered, err := open_run_ledger(logfile, miner_start); err != nil {
		logger.Error(err, "run ledger")
	} else {
		if recovered != nil {
			logger.Info("run ledger: the previous run ended without an exit record", "run_id", recovered.RunID,
				"last", recovered.Last, "uptime_s", recovered.UptimeS, "hashes", recovered.Hashes)
		}
		the_run_ledger = rl
		go run_checkpointer(rl, RUN_CHECKPOINT_EVERY, Exit_In_Progress)
	}

	//threads_ptr := flag.Int("threads", runtime.NumCPU(), "No. Of threads")
	//iterations_ptr := flag.Int("iterations", 20, "No. Of DERO Stereo POW calculated/thread")
	/*bench_ptr := flag.Bool("bench", false, "run bench with params")
	daemon_ptr := flag.String("rpc-server-address", "127.0.0.1:18091", "DERO daemon RPC address to get work and submit mined blocks")
	delay_ptr := flag.Int("delay", 1, "Fetch job every this many seconds")
	wallet_address := flag.String("wallet-address", "", "Owner of this wallet will receive mining rewards")

	_ = daemon_ptr
	_ = delay_ptr
	_ = wallet_address
	*/

	if threads < 1 || iterations < 1 || threads > 2048 {
		panic("Invalid parameters\n")
		//return
	}

	// This tiny goroutine continuously updates status as required
	go func() {
		last_our_height := int64(0)
		last_best_height := int64(0)

		last_counter := uint64(0)
		last_reward_log := time.Now()
		last_total := atomic.LoadUint64(&counter)
		last_stale := stale_sha_now() // r30 B26: TOTAL H/s excludes never-hashed stale-SHA texts (hsreport_r30.go)
		last_total_time := time.Now()
		last_total_cpu := process_cpu_time() // r23 forensics: cpu_cores and H/cpu-s on the TOTAL line (contention.go)
		last_pe := pe_now()                  // r30 B27: P/E CPU split on the TOTAL line
		last_mining_state := false

		_ = last_mining_state

		mining := true
		for {
			select {
			case <-Exit_In_Progress:
				return
			default:
			}

			best_height := int64(0)
			// only update prompt if needed
			if last_our_height != our_height || last_best_height != best_height || last_counter != atomic.LoadUint64(&counter) {
				// choose color based on urgency
				color := "\033[33m"  // default is green color
				pcolor := "\033[32m" // default is green color

				mining_string := ""

				if mining {
					// a 15 s window: over ~1 s the GPU's 4096-hash batches made the figure jump (TOTAL uses 15 s too)
					now, c := time.Now(), effective_hashes(atomic.LoadUint64(&counter), stale_sha_now()) // r30 B26
					speed_ring = append(speed_ring, speed_sample{now, c})
					for len(speed_ring) > 1 && now.Sub(speed_ring[0].t) > 15*time.Second {
						speed_ring = speed_ring[1:]
					}
					mining_speed := 0.0
					if first := speed_ring[0]; now.After(first.t) {
						mining_speed = float64(c-first.c) / now.Sub(first.t).Seconds()
					}
					atomic.StoreUint64(&hashrate_15s_bits, math.Float64bits(mining_speed))
					last_counter = c
					switch {
					case mining_speed > 1000000:
						mining_string = fmt.Sprintf("MINING @ %.3f MH/s", float32(mining_speed)/1000000.0)
					case mining_speed > 1000:
						mining_string = fmt.Sprintf("MINING @ %.3f KH/s", float32(mining_speed)/1000.0)
					case mining_speed > 0:
						mining_string = fmt.Sprintf("MINING @ %.0f H/s", mining_speed)
					}
				}
				last_mining_state = mining

				hash_rate_string := ""

				switch {
				case hash_rate > 1000000000000:
					hash_rate_string = fmt.Sprintf("%.3f TH/s", float64(hash_rate)/1000000000000.0)
				case hash_rate > 1000000000:
					hash_rate_string = fmt.Sprintf("%.3f GH/s", float64(hash_rate)/1000000000.0)
				case hash_rate > 1000000:
					hash_rate_string = fmt.Sprintf("%.3f MH/s", float64(hash_rate)/1000000.0)
				case hash_rate > 1000:
					hash_rate_string = fmt.Sprintf("%.3f KH/s", float64(hash_rate)/1000.0)
				case hash_rate > 0:
					hash_rate_string = fmt.Sprintf("%d H/s", hash_rate)
				}

				testnet_string := ""
				if !globals.IsMainnet() {
					testnet_string = "\033[31m TESTNET"
				}

				src_string := ""
				if globals.Arguments["--gpu"] != nil {
					src_string = fmt.Sprintf("\033[36m[CPU-mb %d GPU-mb %d]\033[0m ", atomic.LoadUint64(&cpu_minis), atomic.LoadUint64(&gpu_minis))
				}
				l.SetPrompt(fmt.Sprintf("\033[1m\033[32mDERO Miner: \033[0m"+color+"Height %d "+pcolor+" BLOCKS %d MiniBlocks %d Rejected %d "+paid_string()+src_string+"\033[32mNW %s %s>%s>>\033[0m ", our_height, block_counter, mini_block_counter, rejected, hash_rate_string, mining_string, testnet_string))
				l.Refresh()
				last_our_height = our_height
				last_best_height = best_height
			}

			publish_status() // the only path by which the metrics handler sees the getwork goroutine's plain globals

			if time.Since(last_reward_log) >= 60*time.Second {
				logRewardStats()
				last_reward_log = time.Now()
			}
			if el := time.Since(last_total_time); el >= 15*time.Second {
				c := atomic.LoadUint64(&counter)
				dc, ds, eff, next_stale := total_window_step(c, last_total, stale_sha_now(), last_stale) // r30 B26: eff = hashes actually completed in the window
				cpuNow := process_cpu_time()
				peNow := pe_now()
				fields := hs_fields(dc, ds, el.Seconds())
				fields = append(fields, contention_fields(eff, cpuNow-last_total_cpu, el.Seconds())...)
				fields = append(fields, pe_fields(last_pe, peNow, el.Seconds())...) // r30 B27
				logger.Info("TOTAL hashrate", fields...)
				last_total_cpu, last_pe, last_stale = cpuNow, peNow, next_stale
				_, ph := phases.snapshot(time.Now(), c)             // r23c payouts: per-phase hashes, not the 50/50 model;
				exp := exp_window.step(c-last_total, ph, hash_rate) // stepped even at D = 0 so no window is priced twice
				exp *= effective_share(eff, dc)                     // r30 B26: never-hashed texts make no share
				if d := hash_rate; d > 0 {                          // hash_rate is the normal difficulty D (nw_from_job)
					exp_shares += exp // outcome.go expectedSharesPhased
					atomic.StoreUint64(&exp_shares_bits, math.Float64bits(exp_shares))
					run_hashes += eff
					run_seconds += el.Seconds()
				}
				last_total = c
				last_total_time = time.Now()
			}
			time.Sleep(1 * time.Second)
		}
	}()

	l.Refresh() // refresh the prompt

	exit_signals := miner_exit_signals(signal.Ignored) // before any Notify: Notify(SIGHUP) clears nohup's SIG_IGN
	go func() {
		var gracefulStop = make(chan os.Signal, 1)
		signal.Notify(gracefulStop, exit_signals...)
		exit_on_signal(gracefulStop, l, request_exit)
	}()

	if threads > 255 {
		logger.Error(nil, "This program supports maximum 256 CPU cores.", "available", threads)
		threads = 255
	}

	go getwork(wallet_address)

	if addr := outcomeAddress(globals.Arguments["--node-rpc-address"], daemon_rpc_address, globals.Config.RPC_Default_Port); addr != "" {
		logger.Info("paid/orphaned from derod", "rpc", addr)
		go pollOutcome(addr, 60*time.Second)
	}

	if bind, ok := globals.Arguments["--metrics-bind"].(string); ok && bind != "" {
		if _, addr, err := start_metrics_server(bind, os.Getenv); err != nil {
			logger.Error(err, "metrics endpoint not started")
		} else {
			logger.Info("metrics endpoint", "metrics", "http://"+addr+"/metrics", "dashboard", "http://"+addr+"/dashboard")
		}
	}

	if globals.Arguments["--gpu"] != nil {
		gpuBin := globals.Arguments["--gpu"].(string)
		mode, _ := globals.Arguments["--gpu-mode"].(string)
		switch {
		case mode == "split" && start_gpu_split(gpuBin): // before the mining threads: its self-test toggles astrobwtv3.SuffixSort
		default:
			if mode != "" && mode != "full" && mode != "split" {
				logger.Error(nil, "unknown --gpu-mode, using full", "mode", mode)
			}
			go mineblock_gpu(gpuBin)
		}
	}

	start_cpu_share_sampler(threads, os.Getenv, func(f func()) { go f() }) // r23b: --cpu-max charged on the CPU the threads got (cpushare.go)
	for i := 0; i < threads; i++ {
		go mineblock(i)
	}
	if cpu_auto || gpu_auto {
		start_duty_tuner(cpu_auto, cpu_floor, gpu_auto, gpu_floor, globals.Arguments["--gpu"] != nil)
	}

	for {
		line, err := l.Readline()
		if err == readline.ErrInterrupt {
			if len(line) == 0 {
				fmt.Print("Ctrl-C received, Exit in progress\n")
				logger.Info("miner exiting", "reason", "Ctrl-C")
				finish_run("Ctrl-C")
				request_exit()
				os.Exit(0)
				break
			} else {
				continue
			}
		} else if err == io.EOF {
			<-Exit_In_Progress
			break
		}

		line = strings.TrimSpace(line)
		line_parts := strings.Fields(line)

		command := ""
		if len(line_parts) >= 1 {
			command = strings.ToLower(line_parts[0])
		}

		switch {
		case line == "help":
			usage(l.Stderr())

		case strings.HasPrefix(line, "say"):
			line := strings.TrimSpace(line[3:])
			if len(line) == 0 {
				fmt.Println("say what?")
				break
			}
		case command == "version":
			fmt.Printf("Version %s OS:%s ARCH:%s \n", config.Version.String(), runtime.GOOS, runtime.GOARCH)

		case is_console_exit_word(line):
			console_exit(line, supervised, os.Stdout, func(reason string) { // r23b: --supervised ignores a typed exit
				finish_run(reason)
				request_exit()
				os.Exit(0)
			})
		case line == "":
		default:
			fmt.Println("you said:", strconv.Quote(line))
		}
	}

	<-Exit_In_Progress

	return

}

// lock_mining_thread pins a mining goroutine to its OS thread only when the thread gets an OS-level setting
// (CPU affinity on linux/windows, a QoS class with --cpu-qos on darwin). On darwin with the default QoS there is
// nothing to keep, and a locked goroutine pays two thread handoffs whenever the scheduler parks it: every 10 ms
// sysmon preempts it (it never yields), and when all Ps are busy (--mining-threads == GOMAXPROCS, the default)
// sysmon also retakes its P during each ~0.3 ms cgo sort, so the return from C stalls in stoplockedm until another
// thread hands the P back. Round 17, 2 threads, contended: unlocked x1.22 median (16 interleaved pairs, all >1).
// The C sort's __thread scratch (dsac/descriptor.c) is then one per Go M rather than one per mining thread; a cgo
// call never leaves its thread, so sharing is impossible (TestUnlockedThreadsBitExact).
func lock_mining_thread() {
	if !should_lock_mining_thread(runtime.GOOS, cpu_qos) {
		return
	}
	runtime.LockOSThread()
	threadaffinity()
}

// should_lock_mining_thread: only an OS-level per-thread setting (affinity on linux/windows, a QoS class on darwin)
// is worth a locked goroutine
func should_lock_mining_thread(goos string, qos int) bool {
	return !(goos == "darwin" && qos == 0)
}

func random_execution(wg *sync.WaitGroup, iterations int) {
	var workbuf [255]byte

	lock_mining_thread()
	yield := new_cgo_yielder() // as mineblock does, so --bench measures the mining loop

	scratch := astrobwt_fast.Pool.Get().(*astrobwt_fast.ScratchData)
	rand.Read(workbuf[:])
	_ = scratch

	ps := astropair.NewScratch()
	var workbuf2 [48]byte
	for i := 0; i < iterations; i++ {
		// a different input every hash, like mining: one fixed buffer measured a single point of the cost distribution
		binary.BigEndian.PutUint32(workbuf[39:43], uint32(i))
		if atomic.LoadInt32(&pair_enabled) == 1 && i+1 < iterations { // the same two-nonce step mineblock takes
			copy(workbuf2[:], workbuf[:48])
			i++
			binary.BigEndian.PutUint32(workbuf2[39:43], uint32(i))
			_, _ = hash_pair(workbuf[:48], workbuf2[:], ps)
			yield.sorted(2)
			continue
		}
		_ = astrobwtv3.AstroBWTv3(workbuf[:48])
		yield.sorted(1)
	}
	wg.Done()
	runtime.UnlockOSThread()
}

// continuously get work

var connection *websocket.Conn
var connection_mutex sync.Mutex

// submitShare sends a found miniblock to the daemon on the reward-critical path.
// It serializes the JSON OFF the write-lock (gorilla requires serialized writes, so we hold
// connection_mutex only for the actual WriteMessage — minimizing lock hold under contention
// from 16+ CPU threads and the GPU worker all racing to submit). It records submit latency for
// observability. The bytes are identical to the old WriteJSON path — same wire format.
func submitShare(jobID, blobHex string, source byte) {
	defer globals.Recover(1)
	if !submit_allowed(submit_bucket, time.Now()) { // r22: a daemon-chosen tiny difficulty cannot flood (job_guard.go)
		return
	}
	data, err := json.Marshal(rpc.SubmitBlock_Params{JobID: jobID, MiniBlockhashing_blob: blobHex})
	if err != nil {
		return
	}
	t0 := time.Now()
	connection_mutex.Lock()
	c := connection
	sent := false
	if c != nil {
		sent = c.WriteMessage(websocket.TextMessage, data) == nil
	}
	connection_mutex.Unlock()
	d := uint64(time.Since(t0).Nanoseconds())
	atomic.AddUint64(&submit_count, 1)
	atomic.AddUint64(&submit_ns_total, d)
	for { // lock-free running max
		m := atomic.LoadUint64(&submit_ns_max)
		if d <= m || atomic.CompareAndSwapUint64(&submit_ns_max, m, d) {
			break
		}
	}
	if sent {
		ledger.add(blobHex, source) // after the write: the hash derod will report this share under, and who found it
	}
}

// low-latency websocket dialer: explicit TCP_NODELAY so a found share is flushed to the
// (loopback) daemon immediately instead of waiting on Nagle coalescing. Go's default dialer
// already sets NoDelay, but we make it explicit + own the dialer (the old code mutated the
// shared websocket.DefaultDialer global, a latent footgun). Short handshake timeout so a dead
// daemon is detected fast and we reconnect quickly.
var minerDialer = &websocket.Dialer{
	HandshakeTimeout: 5 * time.Second,
	TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
	NetDial: func(network, addr string) (net.Conn, error) {
		c, err := net.DialTimeout(network, addr, 5*time.Second)
		if err == nil {
			if tc, ok := c.(*net.TCPConn); ok {
				tc.SetNoDelay(true) // disable Nagle — submit latency over throughput on the share path
			}
		}
		return c, err
	},
}

func getwork(wallet_address string) {

	reconnect_delay := 1 * time.Second // exponential backoff 1s..8s (was a flat 10s)

	for {

		u := url.URL{Scheme: "wss", Host: daemon_rpc_address, Path: "/ws/" + wallet_address}
		logger.Info("connecting to ", "url", u.String())

		// dial into a local and publish it under connection_mutex: submitShare reads `connection` under that lock
		conn, err := dial_getwork(u.String())
		if err != nil {
			atomic.AddUint64(&getwork_reconnects, 1)
			logger.Error(err, "Error connecting to server", "server adress", daemon_rpc_address)
			logger.Info("will retry", "in", reconnect_delay.String(), "server adress", daemon_rpc_address)
			time.Sleep(reconnect_delay)
			if reconnect_delay < 8*time.Second {
				reconnect_delay *= 2
			}
			continue
		}
		reconnect_delay = 1 * time.Second // reset backoff on a successful connect
		connection_mutex.Lock()
		connection = conn
		connection_mutex.Unlock()
		atomic.StoreInt32(&getwork_connected, 1)

		var result rpc.GetBlockTemplate_Result
	wait_for_another_job:

		if err = read_job(conn, GETWORK_READ_TIMEOUT, &result); err != nil {
			logger.Error(err, "connection error")
			atomic.StoreInt32(&getwork_connected, 0)
			atomic.AddUint64(&getwork_reconnects, 1)
			connection_mutex.Lock()
			if connection == conn {
				connection = nil
			}
			connection_mutex.Unlock()
			conn.Close() // every reconnect used to leak the dead socket's fd
			continue
		}
		take_job(result) // r21: validated first; a malformed job crashed every mining thread (job_guard.go)

		//fmt.Printf("recv: %+v diff %d\n", result, Difficulty)
		goto wait_for_another_job
	}

}

// take_job publishes a job read from the daemon to the mining threads, unless validate (accept_job) drops it; it
// reports whether the job was taken. r21: split out of getwork so the validation in front of it is tested.
func take_job(result rpc.GetBlockTemplate_Result) bool {
	if !accept_job(&result) {
		return false
	}

	mutex.Lock()
	job = result
	atomic.AddInt64(&job_counter, 1) // hot loops read it with atomic.LoadInt64, outside mutex
	mutex.Unlock()
	note_job_received(result.JobID, time.Now()) // r23 (job_latency.go)
	atomic.StoreInt64(&job_change_ns, time.Now().UnixNano())
	phase_note(result.Blockhashing_blob)                           // r23b: phase time/hashes, --phase-duty caps (phase_duty.go)
	if e := job_error_to_log(job.LastError, time.Now()); e != "" { // r22: on change or once a minute, clipped
		logger.Error(nil, "received error", "err", e)
	}

	// derod counts per websocket session and restarts at 0 on every reconnect; fold so the totals only grow
	block_counter = blocks_seen.observe(job.Blocks)
	mini_block_counter = minis_seen.observe(job.MiniBlocks) // note if the miner submits the job late, though his counter
	// will increase, but a block has been already found, so
	// orphan miniblocks may be there ( means they will not br rewarded)
	rejected = rejected_seen.observe(job.Rejected)
	hash_rate = nw_from_job(job.Blockhashing_blob, job.Difficultyuint64)
	our_height = int64(job.Height)
	Difficulty = job.Difficultyuint64
	return true
}

// dial_getwork opens the getwork websocket with the per-message read limit (r21: one daemon message was unbounded).
func dial_getwork(u string) (*websocket.Conn, error) {
	conn, _, err := minerDialer.Dial(u, nil)
	if err != nil {
		return nil, err
	}
	conn.SetReadLimit(GETWORK_READ_LIMIT)
	return conn, nil
}

// calcBlockReward mirrors blockchain/transaction_execute.go:42-59 (CalcBlockReward) so the miner can
// estimate DERO earned WITHOUT importing the heavy blockchain package. Verified equal at height 7281276.
const rewardRRI = 210000 * 600 / config.BLOCK_TIME         // RewardReductionInterval
const rewardBase = (41 * 100000 * config.BLOCK_TIME) / 600 // BaseReward (atomic units)

func calcBlockReward(height uint64) uint64 {
	return rewardBase >> ((height + rewardRRI) / rewardRRI)
}

// logRewardStats prints accepted (daemon-authoritative) block/miniblock/reject totals and, when GPU
// mining, the CPU-vs-GPU split by locally-found shares + an estimated DERO value per source.
// Reward per normal miniblock = base_reward/10 (a block = 9 normal + 1 final; share=full_reward/len,
// blockchain/transaction_execute.go:131) — an estimate (ignores tx fees and <10-miniblock blocks).
func logRewardStats() {
	cf := atomic.LoadUint64(&cpu_minis)
	gf := atomic.LoadUint64(&gpu_minis)

	// submit-path latency (lock+serialize+write) for the reward-critical share submit
	if sc := atomic.LoadUint64(&submit_count); sc > 0 {
		avgUs := float64(atomic.LoadUint64(&submit_ns_total)) / float64(sc) / 1000.0
		maxUs := float64(atomic.LoadUint64(&submit_ns_max)) / 1000.0
		logger.Info("SUBMIT STATS", "submits", sc,
			"avg_submit_us", fmt.Sprintf("%.1f", avgUs), "max_submit_us", fmt.Sprintf("%.1f", maxUs))
	}

	h := uint64(our_height)
	if h == 0 {
		return
	}
	perMB := calcBlockReward(h) / 10 // atomic units per accepted miniblock, final ones included
	// a final miniblock ("block") is one of the 10 equal shares too, paid to derod's --integrator-address
	// (blockchain/transaction_execute.go:131-143); counting only normal ones under-reported 0.123 vs 0.1845 DERO
	minisEarned := mini_block_counter * perMB
	finalsEarned := block_counter * perMB
	totalEarned := minisEarned + finalsEarned
	extra := rewardOutcomeFields(perMB, cf+gf)
	if globals.Arguments["--gpu"] == nil {
		logger.Info("REWARD STATS", append([]interface{}{
			"accepted_blocks", block_counter, "accepted_miniblocks", mini_block_counter, "rejected", rejected,
			"est_earned_DERO", globals.FormatMoney(totalEarned), "est_finals_DERO", globals.FormatMoney(finalsEarned),
			"per_miniblock_DERO", globals.FormatMoney(perMB)}, extra...)...)
		return
	}
	total := cf + gf
	var cpuPct, gpuPct float64
	if total > 0 {
		cpuPct = 100 * float64(cf) / float64(total)
		gpuPct = 100 * float64(gf) / float64(total)
	}
	// attribute daemon-accepted miniblocks to sources by locally-found share ratio
	var cpuEarned, gpuEarned uint64
	if total > 0 {
		gpuEarned = totalEarned * gf / total
		cpuEarned = totalEarned - gpuEarned
	}
	logger.Info("REWARD STATS", append([]interface{}{
		"accepted_blocks", block_counter, "accepted_miniblocks", mini_block_counter, "rejected", rejected,
		"found_CPU", cf, "found_GPU", gf, "GPU_share", fmt.Sprintf("%.1f%%", gpuPct),
		"est_earned_DERO", globals.FormatMoney(totalEarned), "est_finals_DERO", globals.FormatMoney(finalsEarned),
		"est_CPU_DERO", globals.FormatMoney(cpuEarned), "est_GPU_DERO", globals.FormatMoney(gpuEarned),
		"per_miniblock_DERO", globals.FormatMoney(perMB)}, extra...)...)
	_ = cpuPct
}

func mineblock(tid int) {
	var diff big.Int
	var work [block.MINIBLOCK_SIZE]byte

	var random_buf [12]byte

	rand.Read(random_buf[:])

	scratch := astrobwt_fast.Pool.Get().(*astrobwt_fast.ScratchData)
	var work2 [block.MINIBLOCK_SIZE]byte // the second nonce of a pair
	pscratch := astropair.NewScratch()   // the pair's two scratch sets (about 1 MB), per thread

	wait_first_job(&job_counter, 5*time.Second, 10*time.Millisecond) // r23: was a fixed 5 s sleep (job_latency.go)

	nonce_buf := work[block.MINIBLOCK_SIZE-5:] //since slices are linked, it modifies parent
	lock_mining_thread()
	yield := new_cgo_yielder() // r21: Gosched every few cgo sorts so sysmon stops taking the P at every sort (cgoyield.go)

	var local_job_counter int64

	i := uint32(0)

	for {
		mutex.RLock()
		myjob := job
		local_job_counter = job_counter
		mutex.RUnlock()

		if !decode_job_blob(&work, myjob.Blockhashing_blob) { // never panics on an oversized blob (job_guard.go)
			logger.Error(nil, "Blockwork could not be decoded successfully", "blob_len", len(myjob.Blockhashing_blob))
			time.Sleep(time.Second)
			continue
		}

		height := binary.BigEndian.Uint64(work[0:]) & 0x000000ffffffffff

		copy(work[block.MINIBLOCK_SIZE-12:], random_buf[:]) // add more randomization in the mix
		work[block.MINIBLOCK_SIZE-1] = byte(tid)

		diff.SetString(myjob.Difficulty, 10)

		if work[0]&0xf != 1 { // check  version
			logger.Error(nil, "Unknown version, please check for updates", "version", work[0]&0x1f)
			time.Sleep(time.Second)
			continue
		}

		// CPU duty-cycle throttle (cpu_throttle): work ~cpu_throttle_window, then sleep so that busy/(busy+sleep) ==
		// the duty cap in force (--cpu-max, moved by the r22 tuner). Only sleeps BETWEEN hashes — the PoW is unchanged.
		throttle_start := time.Now()
		tgt := newPowTarget(&diff) // r22: CheckPowHashBig's verdict without its per-hash big.Int division (powtarget.go)

		if int64(height) < globals.Config.MAJOR_HF2_HEIGHT {
			for local_job_counter == atomic.LoadInt64(&job_counter) { // update job when it comes, expected rate 1 per second
				i++
				binary.BigEndian.PutUint32(nonce_buf, i)

				powhash := astrobwt_fast.POW_optimized(work[:], scratch)
				atomic.AddUint64(&counter, 1)

				cpu_throttle(&throttle_start)

				if tgt.meets(powhash) { // note we are doing a local, NW might have moved meanwhile
					logger.V(1).Info("Successfully found DERO miniblock (going to submit)", "difficulty", myjob.Difficulty, "height", myjob.Height)
					atomic.AddUint64(&cpu_minis, 1)
					submitShare(myjob.JobID, fmt.Sprintf("%x", work[:]), 'C')

				}
			}
		} else {

			for local_job_counter == atomic.LoadInt64(&job_counter) && atomic.LoadInt32(&pair_enabled) == 1 {
				// two nonces per iteration (astropair): work holds nonce i+1, work2 nonce i+2; each hash is checked
				// and submitted on its own, exactly as the single loop below does
				if se := current_split(); se != nil { // --gpu-mode=split: GPU-staged texts first, own nonces when none is staged
					if k := se.TryWork(pscratch); k > 0 {
						atomic.AddUint64(&counter, uint64(k))
						yield.sorted(k)
						cpu_throttle(&throttle_start)
						continue
					}
				}
				i++
				binary.BigEndian.PutUint32(nonce_buf, i)
				work2 = work
				i++
				binary.BigEndian.PutUint32(work2[block.MINIBLOCK_SIZE-5:], i)

				ha, hb := hash_pair(work[:], work2[:], pscratch)
				atomic.AddUint64(&counter, 2)
				yield.sorted(2)

				cpu_throttle(&throttle_start)

				if tgt.meets(ha) {
					logger.V(1).Info("Successfully found DERO miniblock (going to submit)", "difficulty", myjob.Difficulty, "height", myjob.Height)
					atomic.AddUint64(&cpu_minis, 1)
					submitShare(myjob.JobID, fmt.Sprintf("%x", work[:]), 'C')
				}
				if tgt.meets(hb) {
					logger.V(1).Info("Successfully found DERO miniblock (going to submit)", "difficulty", myjob.Difficulty, "height", myjob.Height)
					atomic.AddUint64(&cpu_minis, 1)
					submitShare(myjob.JobID, fmt.Sprintf("%x", work2[:]), 'C')
				}
			}

			for local_job_counter == atomic.LoadInt64(&job_counter) { // update job when it comes, expected rate 1 per second
				i++
				binary.BigEndian.PutUint32(nonce_buf, i)

				powhash := astrobwtv3.AstroBWTv3(work[:])
				atomic.AddUint64(&counter, 1)
				yield.sorted(1)

				cpu_throttle(&throttle_start)

				if tgt.meets(powhash) { // note we are doing a local, NW might have moved meanwhile
					logger.V(1).Info("Successfully found DERO miniblock (going to submit)", "difficulty", myjob.Difficulty, "height", myjob.Height)
					atomic.AddUint64(&cpu_minis, 1)
					submitShare(myjob.JobID, fmt.Sprintf("%x", work[:]), 'C')

				}
			}

		}
	}
}

func usage(w io.Writer) {
	io.WriteString(w, "commands:\n")
	io.WriteString(w, "\t\033[1mhelp\033[0m\t\tthis help\n")
	io.WriteString(w, "\t\033[1mstatus\033[0m\t\tShow general information\n")
	io.WriteString(w, "\t\033[1mbye\033[0m\t\tQuit the miner\n")
	io.WriteString(w, "\t\033[1mversion\033[0m\t\tShow version\n")
	io.WriteString(w, "\t\033[1mexit\033[0m\t\tQuit the miner\n")
	io.WriteString(w, "\t\033[1mquit\033[0m\t\tQuit the miner\n")

}

var completer = readline.NewPrefixCompleter(
	readline.PcItem("help"),
	readline.PcItem("status"),
	readline.PcItem("version"),
	readline.PcItem("bye"),
	readline.PcItem("exit"),
	readline.PcItem("quit"),
)

func filterInput(r rune) (rune, bool) {
	switch r {
	// block CtrlZ feature
	case readline.CharCtrlZ:
		return r, false
	}
	return r, true
}
