// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

//go:build windows
// +build windows

package main

import "time"

func cpuTime() time.Duration { return 0 }
