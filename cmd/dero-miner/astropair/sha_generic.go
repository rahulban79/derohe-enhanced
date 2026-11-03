package astropair

import "github.com/minio/sha256-simd"

func sumGeneric(msg []byte) [32]byte { return sha256.Sum256(msg) }
