//go:build !(darwin && arm64 && cgo)

// Package dsac: the native descriptor sort is built only for darwin/arm64 with cgo; elsewhere it always declines.
package dsac

const Available = false

func SuffixArray(text []byte, sa []int32) bool { return false }

func Release() {}
