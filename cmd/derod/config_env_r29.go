// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8

package main

// r29 (decisions, dero-rft §7 B141, user decision 2026-11-08 (a)): derod refuses to start when the environment moves
// a consensus parameter (config.Settings, read by blockchain/difficulty.go) or when that check cannot run. R27 only
// reported it (config_env_r27.go); a node that computes a different difficulty floor forks itself off the network,
// so starting is now refused. config/ and blockchain/ are unchanged (guard S1).

import (
	"fmt"
	"os"
	"strings"

	"github.com/deroproject/derohe/config"
)

// refuse_on_consensus_env_overrides runs after report_consensus_env_overrides; it calls exit(1) and returns true when
// any consensus Settings field differs from its envDefault (the variables are named, their values are not echoed),
// or when the check itself failed.
func refuse_on_consensus_env_overrides(exit func(int)) bool {
	if consensus_env_check_failed {
		logger.Error(nil, "refusing to start: the consensus settings could not be checked")
		fmt.Fprintln(os.Stderr, "derod: refusing to start: the consensus settings could not be checked")
		exit(1)
		return true
	}
	if consensus_env_overrides == 0 {
		return false
	}
	ov, _ := consensus_setting_overrides(config.Settings)
	names := make([]string, 0, len(ov))
	for _, o := range ov {
		names = append(names, o.Env)
	}
	msg := fmt.Sprintf("refusing to start: the environment overrides consensus parameter(s) %s; unset them (this node would compute a different difficulty than the network)", strings.Join(names, ", "))
	logger.Error(nil, msg)
	fmt.Fprintln(os.Stderr, "derod: "+msg)
	exit(1)
	return true
}
