package main

// Stage-3d bridge validation: drive the GPU binary in server mode from Go (subprocess + stdin/stdout),
// send a batch of random 48-byte blobs, and check every returned hash == astrobwtv3.AstroBWTv3(blob).
// This proves the Go->GPU->Go path is correct end-to-end (the foundation for the --gpu miner worker).
import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/deroproject/derohe/astrobwt/astrobwtv3"
)

func main() {
	const N = 2048
	bin, _ := filepath.Abs("gpu-miner-poc/gpu_hash_sais")
	cmd := exec.Command(bin, "server")
	cmd.Dir = "gpu-miner-poc" // so it finds loop_ops.metal.inc
	cmd.Stderr = os.Stderr
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		fmt.Println("start:", err)
		os.Exit(1)
	}
	out := bufio.NewReaderSize(stdout, N*32+64)

	// build N random 48-byte blobs
	blobs := make([]byte, N*48)
	rand.Read(blobs)
	// frame: [uint32 count][blobs]
	hdr := make([]byte, 4)
	binary.LittleEndian.PutUint32(hdr, uint32(N))

	t0 := time.Now()
	stdin.Write(hdr)
	stdin.Write(blobs)

	res := make([]byte, N*32)
	if _, err := io.ReadFull(out, res); err != nil {
		fmt.Println("read:", err)
		os.Exit(1)
	}
	dt := time.Since(t0)

	// validate every hash
	bad := 0
	for i := 0; i < N; i++ {
		want := astrobwtv3.AstroBWTv3(blobs[i*48 : i*48+48])
		got := res[i*32 : i*32+32]
		for k := 0; k < 32; k++ {
			if want[k] != got[k] {
				bad++
				break
			}
		}
	}
	// close: send count=0 to stop the server
	stdin.Write([]byte{0, 0, 0, 0})
	stdin.Close()
	cmd.Wait()

	fmt.Printf("batch N=%d  round-trip %.3fs (%.0f H/s incl. IPC)  mismatches=%d\n", N, dt.Seconds(), float64(N)/dt.Seconds(), bad)
	if bad == 0 {
		fmt.Println("=== GPU SERVER BRIDGE: all", N, "batch hashes == AstroBWTv3 — Go->GPU path is correct ===")
	} else {
		fmt.Println("=== MISMATCH ===")
		os.Exit(1)
	}
}
