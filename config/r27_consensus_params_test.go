// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8

package config

// r27 (config, dero-rft §7 sweep): config had only an empty Test_Part1, so nothing pinned the consensus parameters
// the round rules depend on (MAJOR_HF3_HEIGHT 7,504,640, BLOCK_TIME 18 s, STABLE_LIMIT 8 ...); the consensus guard
// S1 diffs config/ but a test-level pin was absent. Tests only: this package is consensus-visible.
//
//   TestR27ConsensusConstantsPinned   every consensus constant and both chain configs, by value (strings by SHA-256)
//   TestR27SettingsDefaultsPinned     the env defaults of config.Settings (difficulty floor/bootstrap) and, when no
//                                     override is in the environment, that Settings carries exactly them
//   TestR27VersionRules               the version string: core 3.6.0-153.DEROHE.STARGATE, build metadata
//                                     <DDMMYYYY>.r<N> with a real date
//   TestR27ConsensusConfigReadOnly    no non-test file outside the three known places assigns config.Mainnet,
//                                     config.Testnet, config.Settings or globals.Config

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func r27_sha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func TestR27ConsensusConstantsPinned(t *testing.T) {
	for name, kv := range map[string][2]interface{}{
		"BLOCK_TIME":                   {BLOCK_TIME, uint64(18)},
		"BLOCK_TIME_MILLISECS":         {BLOCK_TIME_MILLISECS, uint64(18000)},
		"MINIBLOCK_HIGHDIFF":           {MINIBLOCK_HIGHDIFF, 9},
		"STABLE_LIMIT":                 {STABLE_LIMIT, int64(8)},
		"MIN_RINGSIZE":                 {MIN_RINGSIZE, 2},
		"MAX_RINGSIZE":                 {MAX_RINGSIZE, 128},
		"FEE_PER_KB":                   {FEE_PER_KB, uint64(20)},
		"MAX_STORAGE_GAS_ATOMIC_UNITS": {MAX_STORAGE_GAS_ATOMIC_UNITS, 20000},
		"STARGATE_HE_MAX_BLOCK_SIZE":   {STARGATE_HE_MAX_BLOCK_SIZE, uint64(10*1024*1024 + 256*1024)},
		"STARGATE_HE_MAX_TX_SIZE":      {STARGATE_HE_MAX_TX_SIZE, 300 * 1024},
		"PREMINE":                      {PREMINE, uint64(1228125400000)},
		"BALANCE_TREE":                 {BALANCE_TREE, "B"},
		"SC_META":                      {SC_META, "M"},
		"Mainnet.HF1_HEIGHT":           {Mainnet.HF1_HEIGHT, int64(21480)},
		"Mainnet.HF2_HEIGHT":           {Mainnet.HF2_HEIGHT, int64(29000)},
		"Mainnet.MAJOR_HF2_HEIGHT":     {Mainnet.MAJOR_HF2_HEIGHT, int64(481600)},
		"Mainnet.MAJOR_HF3_HEIGHT":     {Mainnet.MAJOR_HF3_HEIGHT, int64(7504640)},
		"Testnet.HF1_HEIGHT":           {Testnet.HF1_HEIGHT, int64(0)},
		"Testnet.HF2_HEIGHT":           {Testnet.HF2_HEIGHT, int64(0)},
		"Testnet.MAJOR_HF2_HEIGHT":     {Testnet.MAJOR_HF2_HEIGHT, int64(4)},
		"Testnet.MAJOR_HF3_HEIGHT":     {Testnet.MAJOR_HF3_HEIGHT, int64(0)},
		"Mainnet.Network_ID":           {Mainnet.Network_ID.String(), "59d7f7e9-dd48-d5fd-130a-f6e09a444100"},
		"Testnet.Network_ID":           {Testnet.Network_ID.String(), "59d7f7e9-dd48-d5fd-130a-f6e087000000"},
		"Mainnet.Name":                 {Mainnet.Name, "mainnet"},
		"Mainnet.ports":                {[3]int{Mainnet.GETWORK_Default_Port, Mainnet.RPC_Default_Port, Mainnet.Wallet_RPC_Default_Port}, [3]int{10100, 10102, 10103}},
		// the miniblocks per block the PoW prewarm and Verify_MiniBlocks use: BLOCK_TIME - MINIBLOCK_HIGHDIFF + 1
		"miniblocks per block": {int(BLOCK_TIME - MINIBLOCK_HIGHDIFF + 1), 10},
		// genesis transaction and dev address by digest (no address literal in a test)
		"sha256(Mainnet.Genesis_Tx)":  {r27_sha(Mainnet.Genesis_Tx), r27_mainnet_genesis_sha},
		"sha256(Mainnet.Dev_Address)": {r27_sha(Mainnet.Dev_Address), r27_mainnet_dev_sha},
	} {
		if !reflect.DeepEqual(kv[0], kv[1]) {
			t.Errorf("%s = %v, pinned %v", name, kv[0], kv[1])
		}
	}
	// documented vs used: the mainnet genesis block hash is never set (zero); p2p sends and checks exactly that value
	// as the last chain-locator entry (p2p/chain_sync.go, p2p/rpc_chain_request.go). Pinned so a "fix" that sets it
	// breaks this test before it breaks every chain request with the network.
	var zero [32]byte
	if Mainnet.Genesis_Block_Hash != zero {
		t.Errorf("Mainnet.Genesis_Block_Hash is %x: the network's chain requests carry the zero hash", Mainnet.Genesis_Block_Hash[:])
	}
}

const r27_mainnet_genesis_sha = "cdc9bba8c2aaae31eb86e12e2e34613b4262d73c44729131fee69ff03636d74e"
const r27_mainnet_dev_sha = "666075266fbe59c36361066171467597b55332d180f1282cbc1e2dd427821fd9"

func TestR27SettingsDefaultsPinned(t *testing.T) {
	want := map[string]string{"MAINNET_BOOTSTRAP_DIFFICULTY": "10000000", "MAINNET_MINIMUM_DIFFICULTY": "100000",
		"TESTNET_BOOTSTRAP_DIFFICULTY": "10000", "TESTNET_MINIMUM_DIFFICULTY": "10000"}
	typ, val := reflect.TypeOf(Settings), reflect.ValueOf(Settings)
	if typ.NumField() != len(want) {
		t.Fatalf("SettingsStruct has %d fields, %d pinned: a new environment-settable parameter must be reviewed", typ.NumField(), len(want))
	}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		env, def := f.Tag.Get("env"), f.Tag.Get("envDefault")
		if f.Name != env || want[env] != def {
			t.Errorf("field %s env %q default %q, pinned %q", f.Name, env, def, want[env])
			continue
		}
		if _, set := os.LookupEnv(env); set {
			t.Logf("%s is set in this environment: the effective value is not checked", env)
			continue
		}
		if got := strconv.FormatUint(val.Field(i).Uint(), 10); got != def {
			t.Errorf("Settings.%s = %s with no %s in the environment, want its default %s", f.Name, got, env, def)
		}
	}
}

var r27_build_rx = regexp.MustCompile(`^(\d{2})(\d{2})(\d{4})\.r(\d+[a-z]?)$`)

func TestR27VersionRules(t *testing.T) {
	v := Version
	if v.Major != 3 || v.Minor != 6 || v.Patch != 0 || len(v.Pre) != 3 || v.Pre[0].String() != "153" ||
		v.Pre[1].String() != "DEROHE" || v.Pre[2].String() != "STARGATE" {
		t.Fatalf("version core %d.%d.%d-%v: the handshake compares Major/Minor/Patch/Pre (p2p/rpc_handshake.go), only the build metadata may change", v.Major, v.Minor, v.Patch, v.Pre)
	}
	b := strings.Join(v.Build, ".")
	m := r27_build_rx.FindStringSubmatch(b)
	if m == nil {
		t.Fatalf("build metadata %q is not <DDMMYYYY>.r<round>", b)
	}
	d, err := time.Parse("02012006", m[1]+m[2]+m[3])
	if err != nil || d.Format("02012006") != m[1]+m[2]+m[3] {
		t.Fatalf("build metadata date %q is not a real date: %v", m[1]+m[2]+m[3], err)
	}
	if !strings.HasPrefix(v.String(), "3.6.0-153.DEROHE.STARGATE+") {
		t.Fatalf("String() = %q", v.String())
	}
}

// r27_writers: the only non-test files allowed to assign the chain configs (network selection, the web wallet's
// mainnet default, the simulator's own genesis); everything else must read them.
var r27_writers = map[string]bool{"globals/globals.go": true, "cmd/webwallet/webwallet.go": true, "cmd/simulator/wallets.go": true}
var r27_assign_rx = regexp.MustCompile(`(\bconfig\.(Mainnet|Testnet|Settings)\b(\.\w+)*|\bglobals\.Config\b(\.\w+)*)\s*(=[^=]|\+=|-=|\+\+|--)`)

func TestR27ConsensusConfigReadOnly(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	var bad []string
	err = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if fi.IsDir() {
			if rel == "vendor" || strings.HasPrefix(fi.Name(), ".") && rel != "." {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") || r27_writers[filepath.ToSlash(rel)] {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		for i, l := range strings.Split(string(b), "\n") {
			s := strings.TrimSpace(l)
			if strings.HasPrefix(s, "//") {
				continue
			}
			if r27_assign_rx.MatchString(s) {
				bad = append(bad, filepath.ToSlash(rel)+":"+strconv.Itoa(i+1)+": "+s)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) > 0 {
		t.Fatalf("consensus config assigned outside the known places:\n%s", strings.Join(bad, "\n"))
	}
}
