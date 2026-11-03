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

package walletapi

import "os"
import "fmt"
import "time"
import "sync"
import "runtime"
import "io/ioutil"
import "path/filepath"
import "strings"

import "github.com/deroproject/derohe/cryptography/crypto"
import "github.com/deroproject/derohe/walletapi/mnemonics"

// this is stored in disk in encrypted form
type Wallet_Disk struct {
	*Wallet_Memory
	filename string
	closed   bool // set by Close_Encrypted_Wallet; later saves are refused
	sync.Mutex
}

// when smart contracts are implemented, each will have it's own universe to track and maintain transactions

// this file implements the encrypted data store at rest
func Create_Encrypted_Wallet(filename string, password string, seed *crypto.BNRed) (wd *Wallet_Disk, err error) {

	if _, err = os.Stat(filename); err == nil {
		err = fmt.Errorf("File '%s' already exists", filename)
		return

	} else if os.IsNotExist(err) {
		// path/to/whatever does *not* exist
		// err = fmt.Errorf("path does not exists '%s'", filename)

	}

	wd = &Wallet_Disk{filename: filename}

	// generate account keys
	if wd.Wallet_Memory, err = Create_Encrypted_Wallet_Memory(password, seed); err != nil {
		return nil, err
	}
	wd.Wallet_Memory.wallet_disk = wd

	return
}

// create an encrypted wallet using electrum recovery words
func Create_Encrypted_Wallet_From_Recovery_Words(filename string, password string, electrum_seed string) (wd *Wallet_Disk, err error) {
	wd = &Wallet_Disk{filename: filename}

	language, seed, err := mnemonics.Words_To_Key(electrum_seed)
	if err != nil {
		return
	}
	if wd.Wallet_Memory, err = Create_Encrypted_Wallet_Memory(password, crypto.GetBNRed(seed)); err != nil {
		return nil, err
	}

	wd.Wallet_Memory.account.SeedLanguage = language
	wd.Wallet_Memory.wallet_disk = wd
	return
}

// create an encrypted wallet using using random data
func Create_Encrypted_Wallet_Random(filename string, password string) (wd *Wallet_Disk, err error) {
	wd = &Wallet_Disk{filename: filename}
	if wd.Wallet_Memory, err = Create_Encrypted_Wallet_Memory(password, crypto.RandomScalarBNRed()); err != nil {
		return nil, err // previously dereferenced the nil Wallet_Memory here
	}
	wd.Wallet_Memory.wallet_disk = wd // previously skipped on success, so the wallet was never auto-saved
	return wd, nil
}

// wallet must already be open
func (w *Wallet_Disk) Set_Encrypted_Wallet_Password(password string) (err error) {
	if w != nil {
		w.Wallet_Memory.Set_Encrypted_Wallet_Password(password)
		w.Save_Wallet() // save wallet data
	}
	return
}

func Open_Encrypted_Wallet(filename string, password string) (wd *Wallet_Disk, err error) {
	wd = &Wallet_Disk{filename: filename}
	var filedata []byte

	if _, err = os.Stat(filename); os.IsNotExist(err) {
		err = fmt.Errorf("File '%s' does NOT exists", filename)
		return nil, err
	}

	if filedata, err = ioutil.ReadFile(filename); err != nil {
		return nil, err
	}
	removeStaleTempFiles(filename)

	if wd.Wallet_Memory, err = Open_Encrypted_Wallet_Memory(password, filedata); err != nil {
		return nil, err
	}
	wd.Wallet_Memory.wallet_disk = wd

	return

}

// check whether the already opened wallet can use this password
func (w *Wallet_Disk) Check_Password(password string) bool {
	w.Lock()
	defer w.Unlock()

	return w.Wallet_Memory.Check_Password(password)

}

// save updated copy of wallet
func (w *Wallet_Disk) Save_Wallet() (err error) {
	if w == nil {
		return
	}
	w.Lock()
	defer w.Unlock()

	if w.closed {
		return fmt.Errorf("wallet '%s' is closed", w.filename)
	}

	if err = w.Wallet_Memory.Save_Wallet(); err != nil {
		return
	}

	return writeWalletFileAtomic(w.filename, w.Wallet_Memory.db_memory)
}

// writeWalletFileAtomic replaces filename with data so that a crash or power
// loss at any point leaves either the complete old file or the complete new
// file in place (N5). The old code removed name.bak, renamed name to name.bak
// and then wrote name in place: a crash in between left NO file at the wallet
// path, and a crash during the write left a truncated wallet.
//
// Steps: write a 0600 temp file in the same directory, fsync it, keep the
// previous version as name.bak (hard link, so name never disappears), rename
// the temp file over name (atomic on POSIX; MoveFileEx REPLACE_EXISTING on
// windows) and fsync the directory so the rename itself is durable.
func writeWalletFileAtomic(filename string, data []byte) error {
	return writeWalletFileAtomicWith(filename, data, os.Rename)
}

// writeWalletFileAtomicWith is writeWalletFileAtomic with the final rename
// passed in, so a test can fail it after the temp file is written. A parameter,
// not a package variable: a test seam in a global raced with sync_loop
// goroutines of other tests (r19 storage verifier STOR-2).
func writeWalletFileAtomicWith(filename string, data []byte, rename func(from, to string) error) (err error) {
	dir := filepath.Dir(filename)
	tmp, err := ioutil.TempFile(dir, filepath.Base(filename)+".tmp-*") // created 0600
	if err != nil {
		return err
	}
	tmpname := tmp.Name()
	defer func() {
		if err != nil {
			os.Remove(tmpname)
		}
	}()

	if err = tmp.Chmod(0600); err != nil && runtime.GOOS != "windows" {
		tmp.Close()
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}

	// attempt to protect atleast one backup copy (the previous version)
	if _, serr := os.Stat(filename); serr == nil {
		os.Remove(filename + ".bak")
		if os.Link(filename, filename+".bak") != nil { // no hard links here, or .bak could not be removed
			copyFileReplace(filename, filename+".bak")
		}
	}

	if err = rename(tmpname, filename); err != nil {
		return err
	}
	syncDir(dir)
	return nil
}

// copyFileReplace is the backup fallback for filesystems without hard links.
// It writes a fresh temp file and renames it onto dst, so it never opens an
// existing dst for writing: when dst is still a hard link to the live wallet
// (a crash between Link and Rename, or a dst that could not be removed), an
// O_TRUNC open of dst would truncate the live wallet itself (STOR-2).
func copyFileReplace(src, dst string) {
	data, err := ioutil.ReadFile(src)
	if err != nil {
		return
	}
	tmp, err := ioutil.TempFile(filepath.Dir(dst), filepath.Base(dst)+".tmp-*")
	if err != nil {
		return
	}
	name := tmp.Name()
	_, werr := tmp.Write(data)
	serr := tmp.Sync()
	cerr := tmp.Close()
	if werr != nil || serr != nil || cerr != nil || os.Rename(name, dst) != nil {
		os.Remove(name)
	}
}

// syncDir makes a rename durable; not supported (and not needed) on windows
func syncDir(dir string) {
	if runtime.GOOS == "windows" || runtime.GOOS == "js" {
		return
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
}

// STALE_TEMP_AGE: a temp file younger than this may belong to a save in progress (another process on the same
// wallet), so it is left alone.
const STALE_TEMP_AGE = 2 * time.Minute

// removeStaleTempFiles deletes temp files left by a save interrupted by a crash: exact-prefix matches of
// "<wallet>.tmp-" and "<wallet>.bak.tmp-" in the wallet's directory, older than STALE_TEMP_AGE. The directory is
// listed instead of globbing, so a wallet name with glob metacharacters ([, *, ?) neither misses its temp files nor
// matches other files (W3).
func removeStaleTempFiles(filename string) {
	removeStaleTempFilesAt(filename, time.Now())
}

func removeStaleTempFilesAt(filename string, now time.Time) {
	dir, base := filepath.Dir(filename), filepath.Base(filename)
	entries, err := ioutil.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !(strings.HasPrefix(n, base+".tmp-") || strings.HasPrefix(n, base+".bak.tmp-")) {
			continue
		}
		if now.Sub(e.ModTime()) < STALE_TEMP_AGE {
			continue
		}
		os.Remove(filepath.Join(dir, n))
	}
}

// close the wallet
func (w *Wallet_Disk) Close_Encrypted_Wallet() {
	time.Sleep(time.Second) // give goroutines some time to quit
	w.Save_Wallet()
	w.Wallet_Memory.wallet_disk = nil
	w.Wallet_Memory.Close_Encrypted_Wallet()

	// the final save is done: refuse later saves and scrub the
	// password-derived keys held in memory (best effort; Go may have copies)
	w.Lock()
	w.closed = true
	w.Unlock()
	w.Wallet_Memory.Lock()
	zeroBytes(w.Wallet_Memory.pbkdf2_password)
	zeroBytes(w.Wallet_Memory.master_password)
	w.Wallet_Memory.Unlock()
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
