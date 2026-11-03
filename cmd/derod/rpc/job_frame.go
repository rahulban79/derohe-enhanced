// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.
// GPG: 0F39 E425 8C65 3947 702A  8234 08B2 0360 A03A 9DE8
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
package rpc

// r21 (rpcws): the getwork job frame is serialised ONCE per job. Every miner's frame differs only in the blob (its
// key hash and random nonce) and its three counters, but SendJob ran json.Encoder (reflection over 13 fields, two
// string escapes, a bytes.Buffer) once per miner per job. job_frame encodes every shared field once and builds each
// miner's frame by appending the hex blob and the counters between the pre-encoded pieces. The frame is byte-for-byte
// what job_message produced (TestJobFrameByteIdentical checks it against job_message on random jobs, including
// strings that JSON must escape), so miners see no change.
//
// The per-miner nonce now comes from one 12-byte crypto/rand read instead of three globals.Global_Random.Uint32()
// calls, each of which is an 8-byte crypto/rand read (globals/random.go CryptoRandSource): same source, 1 syscall
// instead of 3.

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strconv"

	"github.com/deroproject/derohe/block"
	"github.com/deroproject/derohe/globals"
	"github.com/deroproject/derohe/rpc"
)

type job_frame struct {
	head     []byte    // {"jobid":...,"blockhashing_blob":"
	mid      []byte    // ","difficulty":...,"epochmilli":N,"blocks":
	tail     [2][]byte // ,"lasterror":...,"status":...}\n  for [registered, unregistered]
	tail_len int
}

const job_unregistered_error = "unregistered miner or you need to wait 15 mins"

func json_str(s string) []byte {
	b, _ := json.Marshal(s) // escapes <, >, & like json.Encoder's default
	return b
}

// new_job_frame pre-encodes base. nil when base has a field the frame layout does not carry (Blocktemplate_blob is
// omitempty and never set by SendJob); the caller then uses job_message.
func new_job_frame(base rpc.GetBlockTemplate_Result) *job_frame {
	if base.Blocktemplate_blob != "" {
		return nil
	}
	f := &job_frame{}
	f.head = append(append([]byte(`{"jobid":`), json_str(base.JobID)...), `,"blockhashing_blob":"`...)
	m := append([]byte(`","difficulty":`), json_str(base.Difficulty)...)
	m = append(m, `,"difficultyuint64":`...)
	m = strconv.AppendUint(m, base.Difficultyuint64, 10)
	m = append(m, `,"height":`...)
	m = strconv.AppendUint(m, base.Height, 10)
	m = append(m, `,"prev_hash":`...)
	m = append(m, json_str(base.Prev_Hash)...)
	m = append(m, `,"epochmilli":`...)
	m = strconv.AppendUint(m, base.EpochMilli, 10)
	m = append(m, `,"blocks":`...)
	f.mid = m
	for i, lasterr := range []string{base.LastError, job_unregistered_error} {
		t := append([]byte(`,"lasterror":`), json_str(lasterr)...)
		t = append(t, `,"status":`...)
		t = append(t, json_str(base.Status)...)
		f.tail[i] = append(t, "}\n"...)
		if len(f.tail[i]) > f.tail_len {
			f.tail_len = len(f.tail[i])
		}
	}
	return f
}

// frame is one miner's text frame; registered=false sets LastError as SendJob does for an unregistered address.
func (f *job_frame) frame(mbl *block.MiniBlock, blocks, miniblocks, rejected uint64, registered bool) []byte {
	blob := mbl.Serialize()
	buf := make([]byte, 0, len(f.head)+2*len(blob)+len(f.mid)+3*20+len(`,"miniblocks":,"rejected":`)+f.tail_len)
	buf = append(buf, f.head...)
	n := len(buf)
	buf = buf[:n+hex.EncodedLen(len(blob))]
	hex.Encode(buf[n:], blob)
	buf = append(buf, f.mid...)
	buf = strconv.AppendUint(buf, blocks, 10)
	buf = append(buf, `,"miniblocks":`...)
	buf = strconv.AppendUint(buf, miniblocks, 10)
	buf = append(buf, `,"rejected":`...)
	buf = strconv.AppendUint(buf, rejected, 10)
	if registered {
		return append(buf, f.tail[0]...)
	}
	return append(buf, f.tail[1]...)
}

// fill_nonce gives each miner different work: one crypto/rand read for all of mbl.Nonce.
func fill_nonce(mbl *block.MiniBlock) {
	var b [4 * len(block.MiniBlock{}.Nonce)]byte
	if _, err := rand.Read(b[:]); err != nil { // never seen; keep the old per-word source rather than send no job
		for i := range mbl.Nonce {
			mbl.Nonce[i] = globals.Global_Random.Uint32()
		}
		return
	}
	for i := range mbl.Nonce {
		mbl.Nonce[i] = binary.LittleEndian.Uint32(b[4*i:])
	}
}
