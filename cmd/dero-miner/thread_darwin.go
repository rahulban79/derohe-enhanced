//go:build darwin
// +build darwin

package main

// macOS has no CPU affinity API; the scheduler places threads by QoS class. --cpu-qos=interactive asks for
// QOS_CLASS_USER_INTERACTIVE (P-core preferred) on each mining thread. It is opt-in
// here because derod usually shares this machine and its block-propagation latency affects orphaning.

/*
#include <pthread.h>
#include <pthread/qos.h>
static int dm_set_qos(int c) {
	qos_class_t q = QOS_CLASS_DEFAULT;
	if (c == 1) q = QOS_CLASS_USER_INITIATED;
	if (c == 2) q = QOS_CLASS_USER_INTERACTIVE;
	return pthread_set_qos_class_self_np(q, 0);
}
*/
import "C"

var processor int32

var cpu_qos = 0 // 0 default (unchanged), 1 user-initiated, 2 user-interactive

func threadaffinity() {
	if cpu_qos > 0 {
		C.dm_set_qos(C.int(cpu_qos))
	}
}
