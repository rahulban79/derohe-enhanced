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

import (
	"strings"
	"testing"

	"github.com/docopt/docopt-go"
)

func parse_derod(t *testing.T, argv ...string) map[string]interface{} {
	t.Helper()
	args, err := docopt.Parse(command_line, append([]string{}, argv...), false, "test", false, false)
	if err != nil {
		t.Fatalf("docopt %v: %v", argv, err)
	}
	return args
}

// TestLogRotationDefaultsMatchUpstream: no flags gives upstream's 100 MB x 2 backups, no age limit, no gzip.
func TestLogRotationDefaultsMatchUpstream(t *testing.T) {
	l, err := log_rotation_from(parse_derod(t), "/x/derod.log")
	if err != nil {
		t.Fatal(err)
	}
	if l.Filename != "/x/derod.log" || l.MaxSize != 100 || l.MaxBackups != 2 || l.MaxAge != 0 || l.Compress {
		t.Fatalf("defaults %+v", l)
	}
	if log_footprint_mb(l) != 300 {
		t.Fatalf("footprint %d, want 300", log_footprint_mb(l))
	}
}

func TestLogRotationFlags(t *testing.T) {
	l, err := log_rotation_from(parse_derod(t, "--log-max-size=20", "--log-max-backups=7", "--log-max-age=14", "--log-compress"), "f")
	if err != nil {
		t.Fatal(err)
	}
	if l.MaxSize != 20 || l.MaxBackups != 7 || l.MaxAge != 14 || !l.Compress {
		t.Fatalf("parsed %+v", l)
	}
	if log_footprint_mb(l) != 160 {
		t.Fatalf("footprint %d, want 160", log_footprint_mb(l))
	}
}

// TestLogRotationRejectsUnbounded: 0 backups (lumberjack: keep all) and out-of-range values are refused.
func TestLogRotationRejectsUnbounded(t *testing.T) {
	for _, bad := range [][]string{
		{"--log-max-backups=0"}, {"--log-max-backups=-1"}, {"--log-max-backups=1001"},
		{"--log-max-size=0"}, {"--log-max-size=10241"}, {"--log-max-size=abc"},
		{"--log-max-age=-1"}, {"--log-max-age=3651"},
	} {
		if l, err := log_rotation_from(parse_derod(t, bad...), "f"); err == nil {
			t.Fatalf("%v accepted: %+v", bad, l)
		} else if !strings.Contains(err.Error(), strings.SplitN(bad[0], "=", 2)[0]) {
			t.Fatalf("%v: error does not name the flag: %v", bad, err)
		}
	}
}

// TestUsageParsesLiveCommandLine: the live node's exact flags still parse next to the new ones, and a boolean flag
// stays boolean. (docopt splits an option line at two spaces; a tab-only separator turned --log-compress into an
// option taking an argument and broke every invocation.)
func TestUsageParsesLiveCommandLine(t *testing.T) {
	args := parse_derod(t, "--data-dir=/d", "--getwork-bind=127.0.0.1:10100", "--rpc-bind=127.0.0.1:10102",
		"--p2p-bind=0.0.0.0:11011", "--integrator-address=dero1x", "--fastsync", "--min-peers=40",
		"--node-tag=test-node", "--lowlatency", "--add-priority-node=203.0.113.164:11011", "--log-dir=/l",
		"--log-compress", "--log-max-size=50")
	if args["--fastsync"] != true || args["--lowlatency"] != true || args["--log-compress"] != true {
		t.Fatalf("boolean flags: fastsync=%v lowlatency=%v log-compress=%v", args["--fastsync"], args["--lowlatency"], args["--log-compress"])
	}
	if args["--log-dir"] != "/l" || args["--min-peers"] != "40" || args["--log-max-size"] != "50" {
		t.Fatalf("parsed %v", args)
	}
}
