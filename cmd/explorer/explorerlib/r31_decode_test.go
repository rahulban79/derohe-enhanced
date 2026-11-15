package explorerlib

import "testing"

// r31 (detector error-paths): a daemon blob that is not hex is an error, never an empty block or transaction.
func TestR31ExplorerDecodeHexBlob(t *testing.T) {
	b, err := decode_hex_blob("block", "0a0b")
	if err != nil || len(b) != 2 || b[0] != 0x0a || b[1] != 0x0b {
		t.Fatalf("valid blob: %x %v", b, err)
	}
	for _, s := range []string{"zz", "0a0", "0x0a"} {
		if b, err := decode_hex_blob("tx", s); err == nil {
			t.Fatalf("%q decoded to %x", s, b)
		}
	}
}
