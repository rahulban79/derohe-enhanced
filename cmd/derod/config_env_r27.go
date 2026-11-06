// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8

package main

// r27 (config, dero-rft §7): config.Settings is filled from the ENVIRONMENT at package init (config/config_main.go
// `env.Parse(&Settings)`), and blockchain.Get_Difficulty_At_Tips reads MAINNET_MINIMUM_DIFFICULTY and
// MAINNET_BOOTSTRAP_DIFFICULTY from it (blockchain/difficulty.go). So a variable left in derod's environment changes
// the difficulty floor this node computes for every block, and the node forks itself off the network: a consensus
// parameter that is not read-only. config/ and blockchain/ are consensus packages and are not changed (guard S1);
// this check only REPORTS, at start, every Settings field whose effective value differs from its envDefault (one
// ERROR line per field, gauge config_consensus_env_overrides). It does not refuse to start: that is the operator's call.

import (
	"fmt"
	"reflect"
	"strconv"

	"github.com/deroproject/derohe/config"
	"github.com/deroproject/derohe/metrics"
)

// SettingOverride is one config.Settings field whose value is not its envDefault.
type SettingOverride struct {
	Env     string // the environment variable (the field's env tag)
	Value   uint64 // the effective value
	Default uint64 // its envDefault
}

// consensus_setting_overrides compares each uint64 field of s with its envDefault tag.
func consensus_setting_overrides(s config.SettingsStruct) (out []SettingOverride, err error) {
	v, t := reflect.ValueOf(s), reflect.TypeOf(s)
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, def := f.Tag.Get("env"), f.Tag.Get("envDefault")
		if name == "" || f.Type.Kind() != reflect.Uint64 {
			continue
		}
		d, perr := strconv.ParseUint(def, 10, 64)
		if perr != nil {
			return nil, fmt.Errorf("config.Settings.%s: envDefault %q is not a uint64", f.Name, def)
		}
		if got := v.Field(i).Uint(); got != d {
			out = append(out, SettingOverride{Env: name, Value: got, Default: d})
		}
	}
	return out, nil
}

var consensus_env_overrides int

func init() {
	metrics.Set.GetOrCreateGauge("config_consensus_env_overrides", func() float64 { return float64(consensus_env_overrides) })
}

// report_consensus_env_overrides logs one ERROR line per overridden field and sets the gauge.
func report_consensus_env_overrides() {
	ov, err := consensus_setting_overrides(config.Settings)
	if err != nil {
		logger.Error(err, "cannot check the consensus settings")
		return
	}
	consensus_env_overrides = len(ov)
	for _, o := range ov {
		logger.Error(nil, "consensus parameter overridden by the environment: this node will compute a different difficulty than the network",
			"env", o.Env, "value", o.Value, "default", o.Default)
	}
}
