// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8

package globals

// r27 (glue-global): globals/ was 0.7% covered. Time() is the clock the block and miniblock "from the future" checks
// read, so its offset rules are pinned here by tests only (its code is unchanged). Every clock assertion brackets
// Time() between two time.Now() reads shifted by the offset: deterministic, no sleep, no wall-clock tolerance.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/metrics"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/net/proxy"
)

// clock_state saves and restores every global the clock tests touch.
func clock_state(t *testing.T) {
	ntp, p2p, flag, insync, insyncntp := GetOffsetNTP(), GetOffsetP2P(), atomic.LoadUint32(&ntp_in_sync), TimeIsInSync, TimeIsInSyncNTP
	t.Cleanup(func() {
		atomic.StoreInt64((*int64)(&ClockOffsetNTP), int64(ntp))
		atomic.StoreInt64((*int64)(&ClockOffsetP2P), int64(p2p))
		atomic.StoreUint32(&ntp_in_sync, flag)
		TimeIsInSync, TimeIsInSyncNTP = insync, insyncntp
	})
	atomic.StoreInt64((*int64)(&ClockOffsetNTP), 0)
	atomic.StoreInt64((*int64)(&ClockOffsetP2P), 0)
	atomic.StoreUint32(&ntp_in_sync, 0)
	TimeIsInSync, TimeIsInSyncNTP = false, false
}

// within reports whether clock() lies in [now+off, now'+off] for the two local reads around it.
func within(clock func() time.Time, off time.Duration) bool {
	before := time.Now()
	got := clock()
	after := time.Now()
	return !got.Before(before.Add(off)) && !got.After(after.Add(off))
}

func TestR27TimeOffsetRules(t *testing.T) {
	clock_state(t)
	const hour = time.Hour
	for name, clock := range map[string]func() time.Time{"Time": Time, "TimeSkipP2P": TimeSkipP2P} {
		atomic.StoreUint32(&ntp_in_sync, 0)
		atomic.StoreInt64((*int64)(&ClockOffsetNTP), int64(hour)) // a stored value is NOT applied before NTP marks it usable
		TimeIsInSync = false
		if !within(clock, 0) {
			t.Fatalf("%s: offset applied before NTP was marked in sync", name)
		}
		SetClockOffsetNTP(hour)
		if !within(clock, hour) {
			t.Fatalf("%s: NTP offset +1h not applied", name)
		}
		SetClockOffsetNTP(-hour)
		if !within(clock, -hour) {
			t.Fatalf("%s: NTP offset -1h not applied", name)
		}
		SetClockOffsetP2P(3 * hour) // the peer average is computed and published, never applied
		if !within(clock, -hour) {
			t.Fatalf("%s: the P2P offset leaked into the clock", name)
		}
		TimeIsInSync = true // --timeisinsync: the local clock, whatever was measured
		if !within(clock, 0) {
			t.Fatalf("%s: --timeisinsync still applied an offset", name)
		}
		TimeIsInSync = false
		atomic.StoreUint32(&ntp_in_sync, 0)
		TimeIsInSyncNTP = true // the legacy flag alone also makes the NTP value usable
		if !within(clock, -hour) {
			t.Fatalf("%s: TimeIsInSyncNTP did not enable the NTP offset", name)
		}
		TimeIsInSyncNTP = false
	}
}

// run under -race: the NTP and P2P writers against the consensus readers (r20 made them atomic).
func TestR27ClockOffsetRace(t *testing.T) {
	clock_state(t)
	var wg sync.WaitGroup
	for w := 0; w < 2; w++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				SetClockOffsetNTP(time.Duration(i) * time.Microsecond)
				SetClockOffsetP2P(time.Duration(-i) * time.Microsecond)
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				_ = Time()
				_ = TimeSkipP2P()
				_ = GetOffset() + GetOffsetNTP() + GetOffsetP2P()
			}
		}()
	}
	wg.Wait()
}

func args_state(t *testing.T) {
	saved, cfg, dialer, logger := Arguments, Config, Dialer, Logger
	lc, lf := Log_Level_Console, Log_Level_File
	t.Cleanup(func() {
		Arguments, Config, Dialer, Logger = saved, cfg, dialer, logger
		Log_Level_Console, Log_Level_File = lc, lf
	})
	Arguments = map[string]interface{}{}
}

func TestR27InitNetwork(t *testing.T) {
	args_state(t)
	for _, c := range []struct {
		arg  interface{}
		want string
	}{{nil, config.Mainnet.Name}, {false, config.Mainnet.Name}, {true, config.Testnet.Name}, {"true", config.Mainnet.Name}} {
		Arguments = map[string]interface{}{}
		if c.arg != nil {
			Arguments["--testnet"] = c.arg
		}
		Config = config.CHAIN_CONFIG{}
		InitNetwork()
		if Config.Name != c.want || IsMainnet() != (c.want == config.Mainnet.Name) {
			t.Fatalf("--testnet=%v: network %q, want %q", c.arg, Config.Name, c.want)
		}
	}
}

func TestR27InitializeDataDirAndProxy(t *testing.T) {
	args_state(t)
	dir := t.TempDir()
	Arguments["--data-dir"] = dir
	Arguments["--testnet"] = true
	Arguments["--simulator"] = true
	Arguments["--socks-proxy"] = "localhost:9050" // proxy.FromURL builds a dialer; nothing connects
	Initialize()
	want := filepath.Join(dir, "testnet_simulator")
	if GetDataDirectory() != want || !IsSimulator() || IsMainnet() {
		t.Fatalf("data dir %q simulator %v mainnet %v", GetDataDirectory(), IsSimulator(), IsMainnet())
	}
	if st, err := os.Stat(want); err != nil || !st.IsDir() {
		t.Fatalf("Initialize did not create %s: %v", want, err)
	}
	if Dialer == proxy.Direct {
		t.Fatalf("--socks-proxy left the direct dialer in place")
	}
	delete(Arguments, "--testnet")
	delete(Arguments, "--simulator")
	InitNetwork()
	if GetDataDirectory() != filepath.Join(dir, "mainnet") {
		t.Fatalf("mainnet data dir %q", GetDataDirectory())
	}
}

func TestR27InitializeLogLevelsAndCaller(t *testing.T) {
	args_state(t)
	for _, c := range []struct {
		args              map[string]interface{}
		console, filelvel int8
	}{
		{map[string]interface{}{}, 0, -1},
		{map[string]interface{}{"--debug": true}, -1, -1},
		{map[string]interface{}{"--clog-level": "2", "--flog-level": "3"}, -2, -3},
		{map[string]interface{}{"--clog-level": "-5", "--flog-level": "-1"}, 0, 0}, // negative input clamps to 0
	} {
		Arguments = c.args
		Log_Level_Console, Log_Level_File = zap.NewAtomicLevelAt(zapcore.Level(0)), zap.NewAtomicLevelAt(zapcore.Level(-1))
		var con, file bytes.Buffer
		InitializeLog(&con, &file)
		if int8(Log_Level_Console.Level()) != c.console || int8(Log_Level_File.Level()) != c.filelvel {
			t.Fatalf("args %v: console %d file %d, want %d %d", c.args, Log_Level_Console.Level(), Log_Level_File.Level(), c.console, c.filelvel)
		}
		Logger.Info("r27 probe", "k", 1)
		if !strings.Contains(con.String(), "r27 probe") || strings.Contains(con.String(), "r27_globals_test.go") {
			t.Fatalf("console line %q: want the message without caller", con.String())
		}
		var rec map[string]interface{}
		if err := json.Unmarshal(bytes.TrimSpace(file.Bytes()), &rec); err != nil || !strings.Contains(fmt.Sprint(rec["C"]), "r27_globals_test.go") {
			t.Fatalf("file line %q (%v): want JSON with the caller", file.String(), err)
		}
	}
}

func TestR27RecoverCounts(t *testing.T) {
	args_state(t)
	c := metrics.Set.GetOrCreateCounter(`recovered_panics_total{level="7"}`)
	before := c.Get()
	func() {
		defer Recover(7) // the way every caller uses it: the panic stops here and is counted
		panic("r27")
	}()
	if c.Get() != before+1 {
		t.Fatalf("Recover: counter %d -> %d", before, c.Get())
	}
	if Recover(7) != nil { // no panic in flight
		t.Fatalf("Recover without a panic returned an error")
	}
}

func TestR27CryptoRandSource(t *testing.T) {
	s := NewCryptoRandSource()
	s.Seed(1) // no-op
	for i := 0; i < 1000; i++ {
		if s.Int63() < 0 {
			t.Fatalf("negative Int63")
		}
	}
	if n := Global_Random.Intn(10); n < 0 || n >= 10 {
		t.Fatalf("Intn %d", n)
	}
}
