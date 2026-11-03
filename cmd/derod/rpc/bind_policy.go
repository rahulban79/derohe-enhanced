package rpc

// Exposure policy for derod's HTTP listeners (Round 18). Local policy only.
//
// The daemon RPC registers net/http/pprof unless DISABLE_RUNTIME_PROFILE=1. On the default loopback bind that is a
// developer convenience; on a public --rpc-bind it hands anyone goroutine stacks, heap dumps, the full command line
// and 30-second CPU profiles/traces on demand. pprof is now kept off a non-loopback bind unless the operator opts in
// with ENABLE_PUBLIC_RUNTIME_PROFILE=1. Loopback behaviour is unchanged.
//
// The getwork server defaults to 0.0.0.0:10100 with no authentication: anyone who can reach it can take jobs and
// submit miniblocks, each of which costs this node one full AstroBWT verification (Accept_new_block checks the job
// cache, then VerifyMiniblockPoW). That is upstream's design for LAN/pool mining, so it stays, but it is now
// announced at startup.

import "net"
import "strings"

import "github.com/deroproject/derohe/glue/rwc"

// Message-size ceilings. The largest legitimate request is a hex-encoded SubmitBlock: 2 x STARGATE_HE_MAX_BLOCK_SIZE
// (10.25 MiB) plus framing, so the HTTP and websocket RPC share glue/rwc's 32 MiB ceiling (a 16 MiB cap would have
// refused a maximum-size block).
const RPC_READ_LIMIT = rwc.MaxMessageSize
const GETWORK_READ_LIMIT = 1 << 20

func bind_is_loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// pprof_allowed decides whether runtime profiling handlers are registered on the RPC listener.
func pprof_allowed(bind string, getenv func(string) string) bool {
	if getenv("DISABLE_RUNTIME_PROFILE") == "1" {
		return false
	}
	return bind_is_loopback(bind) || getenv("ENABLE_PUBLIC_RUNTIME_PROFILE") == "1"
}
