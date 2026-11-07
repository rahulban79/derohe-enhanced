// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package mempool

import (
	"encoding/hex"
	"testing"

	"github.com/deroproject/derohe/transaction"
)

// Round 28 (dvm-blockchain, dero-rft §7 B19): the pool's fee rank is the INTEGER fee / serialised size
// (Mempool_Add_TX), so every fee below one atomic unit per byte ranks 0 and the template order among them is the
// sync.Map range order, not the fee. Pinned as it is: blockchain/mempool/ is a guarded package (consensus guard S1),
// so changing the rank is a user decision (B19), never a local patch. The tx is Test_mempool's testnet tx; only its
// fee field is changed (the pool does not verify proofs).
func TestR28FeeRankIsIntegerPerByte(t *testing.T) {
	raw, _ := hex.DecodeString(r28_tx_hex)
	rank := func(fee uint64) (uint64, uint64) {
		var tx transaction.Transaction
		if err := tx.Deserialize(raw); err != nil {
			t.Fatal(err)
		}
		tx.Payloads[0].Statement.Fees = fee
		pool, err := Init_Mempool(nil)
		if err != nil {
			t.Fatal(err)
		}
		if !pool.Mempool_Add_TX(&tx, 0) {
			t.Fatal("add refused")
		}
		info := pool.Mempool_List_TX_SortedInfo()
		if len(info) != 1 {
			t.Fatalf("sorted info has %d entries", len(info))
		}
		return info[0].FeesPerByte, info[0].Size
	}
	_, size := rank(0)
	if size < 1000 {
		t.Fatalf("premise: the tx is %d bytes", size)
	}
	// the size includes the fee's own varint, so each case is judged against the size the pool measured for it
	zero_upto := uint64(0)
	for _, fee := range []uint64{0, 1, size / 2, size - 3, size - 1, size, size + 5, 2*size - 1, 2*size + 9, 10*size + 7} {
		got, sz := rank(fee)
		if got != fee/sz {
			t.Fatalf("fee %d on %d bytes ranks %d, want %d (integer fee/size)", fee, sz, got, fee/sz)
		}
		if got == 0 && fee > zero_upto {
			zero_upto = fee
		}
	}
	if zero_upto < size-3 {
		t.Fatalf("premise: a fee of %d (just under 1 unit/byte) ranks above 0", size-3)
	}
	t.Logf("B19 fee rank: a %d-byte tx ranks 0 for every fee up to at least %d atomic units", size, zero_upto)
}

const r28_tx_hex = "01000003519b9e874a9dd7fcbfb7802268123dcf970c336891101a3a0705855b72b9eb08c80100000000000000000000000000000000000000000000000000000000000000000000f394d06566a81b024fd8624b4c8592f8b9344e58f227261eb08d821bd190b4ac9c7df0660038ddcf881602a14fe5ad8eebff83d3ce3541a1f232fe61acf71109e417160936863e8c0597c798b73ef08e76b8eeebcaf20260ba91fcdef5f626361f824dc6197b02c599d4511c624a933226d8fccc125611ec80d8ad5acea4baf2f1c77e4c5525d9859b40f43daaf3d4e4450203d80419dcb026b9adbd7d6912284ee9ce20f3721076947f16e1faefd9b8c35116f4cf0044ead0a12fda3f3bcf2ed91627b922c02c10d112df9e782d3750cda151f6ba2ebe6495065141f32800894566011198c4055458005a31d3e285037446ba14bac54420bcab87cbebeaccab1f158b011e90132b7310e6c866e348cab68d21bad1d9f811b4d667a1e40bdef1a19259d3000b972ae06da958658b12ca4a45c2c6ea50d305be86f7e979fc962c687eb012f401a2c4bf0beb6c713343b94d65ee6d937660480daf670ab5b0ed421a9103e8a25119c836dd799600e67e4ec66ef680833398a99b16956aed2ee5bd9e6c8e68009a01145636e5e448d6c8ab902db394aa9c5aeee92dd150e1150d5b8f6674f330c279010912df27232ae126525a130ed8a9b4dee62eb57ce1d8a42ae9bcef867b10ce94012f94aa78846fcdda504243f83f3122aee5dc38dd32fa2a90224b3a40b4cf79c301129028709e39591c55e6e477a36cc26dc2efd7183fb59f51635dbd114dfed9d5010d66f31b781fa181c2114600ee1f03d55439355265700fb9d35ac684a19db398001e12558cc17e59fb85fb825481dee6fef3612c043bb38ca4833183da5381364600077a99d4d2df2f06067359f178a40f98a3e0943309c5ce3ce5398b9909174254012aa49cfc78ebec51c00e7824db0d8d41ef43fbb0396824d2c31b7db64124cc61000a8b51bd6c94a502f7aea3e5001f00d76b165ad580e48f8aa72813da8240286e00055f3480aa7cdb68a20d4b1e567d42389b44cf4e345da9e5a5655a80418695bc012c8f1e1ef8af646b4fb08afaeb3febde17c4c0d04b30dfd22d96a32ced9c9439010c40484e1547d307ad56b79bb7450e4eaaed7ed79bd5392dffd7449043f8783a0015104264f8d80356176ca6fdf4777e4ebc8edcbab50f8b6c366ac75ebd6bb5c701078d55053d2d41f21f51d5e617f282ba9dfa2576f0231048dd73998ceaa699fd0105821b61addd6935c7d80e65c706f0f2aa2d73ad22c5548c9c8b92cd82689dc40115f576c413a37014b9ee5377b121c69ad6e0f00f2b4f6c99d1f68b00a5d923370119b29fe6e9cf35f1344e24d52ee1fdb6521de3176f3d2b2a2b9327ae6e6cfbb10017198369a6ff180253700361c40e7f378c8e7ead6e04f01dbf5b4c47e7e1e4ff001abaf84628764eccbc5d0f66dc0a99505bb0e598362c45312470526afad11caf00242c6a902c564b3b363eb4ae08f643f18571779428358bfbdaf9856b0ebf229f0100000000000000000000000000000000000000000000000000000000000000001b7a78b6f573d4ac5d3a8d7d10dafac0dbc92604474417b29d40448d9fbc821d0fe3f73da41b27752d5db0658fcc0bff7da21112417ac719e491fdd43c8e5d0b07bcca22c27367a276e6a4e0cfb1bfbc772842898356ad4723101d4ada5137f409bb3b290d7519da3af15feb09e183e2be809690099551f1cb984deb1295b7611dd0cfd9000482314a388512d278fc22b2f6e3fc6e95023b4bd228e22626b7440119fa2c6f45a33b008ef5b23a5522ebbf0bf5f26d8263613a7f9b5ad9a192357600107a023453f7f79f413756dfba0096ae5d13158bbbb147089a020e819ef6640728acf01c811b967d1a14d767ac20088c5ca1613aa5d94ebe7fe2840b6431d8d002137dae183071d12cd9fb14c4b4738ef750ff514ce26257d1245eaedfea625516bfcb075a33a8910dc4e40742bfaa70d95591711e9db33d0db0be06cc819817072c22a9c81f4369f68bb1ef71c7f7458671d647caef18b30cca91da4f1b201d082a03306b4a07d1f0e1a8cc8844038fc524201a6c3a346a971203fd45458d292987d44049eecdac25c5622465a8d683a43621612d2fb283724b17a7bfa3bad2266a6fb1cf669eef21c90e24e85d6ab48e8b237355e964407dde00d65fb442dd210ce0378349f533c0e8ab65293de5319e246a044ed22b1e6db28add1508dd6f0da22954eea8a431b211a8b54147e32fec6593f9fb731389f62f94d5047e0f3301216576c71a79629bc3879325280e216d59cf7e6ff2d6a0babe418f8f2ed603ce010e16785f8c855043221ed5a603d4ed4e8e90059669543738ceb2a04dc996079c01264e9beaf4bb82e1b8f47bb0c239167064001e306eeef2b5495ec42754806b65012357f738543b13594ff081a070dbc0575645ac5ce8e0f89d3afdeb3d49e9ddae012a17d5095b9cef08f6eee2ce733dbf2cfcdb8c23e39410ed973e68cf8505266d00280c52b45752dd12ba84499618898111a8f9b19f2b76c06917e57eef221f3387011cc3360b478d144118a82a3c4391814f34aac2fb0f2d043394304bed179689e501292ca5631820f5f465242b4cc517f06c153c176a43f77daca463b7e2d3e2d7ba001aa0b2c90c3172cd2556137d78748f47924432449210d8b2f5e27adb6210bc77012c92a12526a5b0b1ef60994eb4d08e9bb5a3ea330d417838a52ad8636d37fa9e00131153c9affeefd6b98ecb6a80f5e6ea97417376030325182c064e12dd353c32011f4e25c49eea09adaa46d56642e2ea0afced2d75036acd3839435863f1ec3bf1002e19fe8456a7236c8fb77a15f87164debaad865e85c3468152a5deaffde3da6a01"
