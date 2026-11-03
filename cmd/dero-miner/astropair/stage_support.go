package astropair

// Package-level names that the generated stage 1 refers to, mirroring pow.go (CALCULATE_DISTRIBUTION is false
// there too, so the two branches that use ops and steps compile away).
const CALCULATE_DISTRIBUTION = false

var ops [256]int
var steps = map[uint64]int{}
