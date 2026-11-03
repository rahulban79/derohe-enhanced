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

//go:build darwin
// +build darwin

package metrics

// The vendored VictoriaMetrics library writes process_* metrics only on Linux and Windows
// (process_metrics_other.go is empty), so a macOS node exported no CPU, memory or descriptor numbers at all and a
// 26-hour RSS question could only be answered with ps at that moment. getrusage gives the CPU split and the peak
// resident size (bytes on darwin); /dev/fd lists the open descriptors. Names match the Linux exporter.

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"syscall"
	"unsafe"
)

func write_os_process_metrics(w io.Writer) {
	var ru syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &ru) == nil {
		user := float64(ru.Utime.Sec) + float64(ru.Utime.Usec)/1e6
		sys := float64(ru.Stime.Sec) + float64(ru.Stime.Usec)/1e6
		fmt.Fprintf(w, "process_cpu_seconds_user_total %g\n", user)
		fmt.Fprintf(w, "process_cpu_seconds_system_total %g\n", sys)
		fmt.Fprintf(w, "process_cpu_seconds_total %g\n", user+sys)
		fmt.Fprintf(w, "process_resident_memory_peak_bytes %d\n", ru.Maxrss) // darwin reports bytes, Linux KiB
		fmt.Fprintf(w, "process_major_pagefaults_total %d\n", ru.Majflt)
		fmt.Fprintf(w, "process_minor_pagefaults_total %d\n", ru.Minflt)
	}
	if virt, rss, ok := task_memory(os.Getpid()); ok { // r21: the current size, not only the peak (a leak can now shrink back)
		fmt.Fprintf(w, "process_resident_memory_bytes %d\n", rss)
		fmt.Fprintf(w, "process_virtual_memory_bytes %d\n", virt)
	}
	if n, err := open_fds(); err == nil {
		fmt.Fprintf(w, "process_open_fds %d\n", n)
	}
	var rl syscall.Rlimit
	if syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl) == nil {
		fmt.Fprintf(w, "process_max_fds %d\n", rl.Cur)
	}
	fmt.Fprintf(w, "process_start_time_seconds %d\n", startTime.Unix())
}

// open_fds counts the entries of /dev/fd, minus the descriptor used to read it.
func open_fds() (int, error) {
	f, err := os.Open("/dev/fd")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return 0, err
	}
	return len(names) - 1, nil
}

// r21 (storageops): getrusage has only the PEAK resident size, which can never go down, so a 50-minute RSS trend of
// the live node was unreadable from /metrics (ps was needed). proc_pidinfo(PROC_PIDTASKINFO) returns struct
// proc_taskinfo, whose first two fields are pti_virtual_size and pti_resident_size (uint64, bytes); the libproc
// wrapper is the proc_info syscall with callnum PROC_INFO_CALL_PIDINFO (2) and flavor PROC_PIDTASKINFO (4).
const (
	proc_info_call_pidinfo = 2
	proc_pidtaskinfo       = 4
	proc_taskinfo_size     = 96 // sizeof(struct proc_taskinfo)
)

func task_memory(pid int) (virt, rss uint64, ok bool) {
	var buf [proc_taskinfo_size]byte
	n, _, e := syscall.Syscall6(syscall.SYS_PROC_INFO, proc_info_call_pidinfo, uintptr(pid), proc_pidtaskinfo, 0,
		uintptr(unsafe.Pointer(&buf[0])), proc_taskinfo_size)
	return parse_taskinfo(buf[:], int(n), e)
}

// parse_taskinfo is split out so the size check is unit-tested: a short or failed reply is never reported as 0 bytes.
func parse_taskinfo(buf []byte, n int, e syscall.Errno) (virt, rss uint64, ok bool) {
	if e != 0 || n < 16 || len(buf) < 16 {
		return 0, 0, false
	}
	return binary.LittleEndian.Uint64(buf[0:8]), binary.LittleEndian.Uint64(buf[8:16]), true
}
