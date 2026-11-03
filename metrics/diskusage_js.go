//go:build js
// +build js

package metrics

// js/wasm has no statfs: the wasm wallet builds report zero disk usage instead of failing to compile (r18 DEP-11).

// DiskUsage contains usage data and provides user-friendly access methods
type DiskUsage struct{}

// NewDiskUsage returns an empty usage object on js/wasm
func NewDiskUsage(volumePath string) *DiskUsage { return &DiskUsage{} }

// Free returns total free bytes on file system (unknown on js: 0)
func (du *DiskUsage) Free() uint64 { return 0 }

// Available return total available bytes on file system to an unprivileged user (unknown on js: 0)
func (du *DiskUsage) Available() uint64 { return 0 }

// Size returns total size of the file system (unknown on js: 0)
func (du *DiskUsage) Size() uint64 { return 0 }

// Used returns total bytes used in file system (unknown on js: 0)
func (du *DiskUsage) Used() uint64 { return 0 }

// Usage returns percentage of use on the file system (unknown on js: 0)
func (du *DiskUsage) Usage() float32 { return 0 }
