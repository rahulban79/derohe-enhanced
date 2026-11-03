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

// r20: configurable log rotation.
//
// Upstream hard-codes lumberjack MaxSize 100 MB, MaxBackups 2, no age limit and no compression. That bounds the log
// at 300 MB, but nothing else can be chosen: an operator who wants a week of history in 50 MB, or compressed
// backups, has to patch the binary. The flags below default to exactly upstream's values. MaxBackups 0 is refused:
// lumberjack reads it as "keep every backup", and with --log-max-age=0 that is an unbounded log directory.

import (
	"fmt"
	"strconv"

	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	LOG_MAX_SIZE_MB_DEFAULT = 100
	LOG_MAX_BACKUPS_DEFAULT = 2
	LOG_MAX_SIZE_MB_LIMIT   = 10240
	LOG_MAX_BACKUPS_LIMIT   = 1000
	LOG_MAX_AGE_DAYS_LIMIT  = 3650
)

// log_rotation_from parses --log-max-size, --log-max-backups, --log-max-age and --log-compress into a lumberjack
// logger for filename.
func log_rotation_from(args map[string]interface{}, filename string) (*lumberjack.Logger, error) {
	l := &lumberjack.Logger{Filename: filename, MaxSize: LOG_MAX_SIZE_MB_DEFAULT, MaxBackups: LOG_MAX_BACKUPS_DEFAULT}
	num := func(flag string, def, min, max int) (int, error) {
		v, ok := args[flag].(string)
		if !ok || v == "" {
			return def, nil
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < min || n > max {
			return 0, fmt.Errorf("%s must be an integer from %d to %d, got %q", flag, min, max, v)
		}
		return n, nil
	}
	var err error
	if l.MaxSize, err = num("--log-max-size", LOG_MAX_SIZE_MB_DEFAULT, 1, LOG_MAX_SIZE_MB_LIMIT); err != nil {
		return nil, err
	}
	if l.MaxBackups, err = num("--log-max-backups", LOG_MAX_BACKUPS_DEFAULT, 1, LOG_MAX_BACKUPS_LIMIT); err != nil {
		return nil, err
	}
	if l.MaxAge, err = num("--log-max-age", 0, 0, LOG_MAX_AGE_DAYS_LIMIT); err != nil {
		return nil, err
	}
	if c, ok := args["--log-compress"].(bool); ok {
		l.Compress = c
	}
	return l, nil
}

// log_footprint_mb is the most disk the log can take: the live file plus MaxBackups backups (uncompressed).
func log_footprint_mb(l *lumberjack.Logger) int { return l.MaxSize * (l.MaxBackups + 1) }
