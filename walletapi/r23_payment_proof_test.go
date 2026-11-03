// Copyright 2017-2021 DERO Project. All rights reserved.
// Use of this source code in any form is governed by RESEARCH license.
// license can be found in the LICENSE file.

package walletapi

import (
	"math/big"
	"testing"

	"github.com/deroproject/derohe/cryptography/bn256"
	"github.com/deroproject/derohe/cryptography/crypto"
	"github.com/deroproject/derohe/rpc"
	"github.com/deroproject/derohe/transaction"
)

// synthetic_payment builds the commitment layout of one transfer: C[k] = v*G + r*Y_k, D = r*G, receiver at index 1.
func synthetic_payment(v uint64) (tx *transaction.Transaction, ring [][]*bn256.G1, sk *big.Int, honest *bn256.G1) {
	sk = crypto.RandomScalar()
	r := crypto.RandomScalar()
	ring = [][]*bn256.G1{make([]*bn256.G1, 4)}
	st := crypto.Statement{D: new(bn256.G1).ScalarMult(crypto.G, r)}
	for k := 0; k < 4; k++ {
		y := new(bn256.G1).ScalarMult(crypto.G, crypto.RandomScalar())
		amt := uint64(0)
		if k == 1 {
			y = new(bn256.G1).ScalarMult(crypto.G, sk)
			amt = v
		}
		ring[0][k] = y
		c := new(bn256.G1).Add(new(bn256.G1).ScalarMult(crypto.G, new(big.Int).SetUint64(amt)), new(bn256.G1).ScalarMult(y, r))
		st.C = append(st.C, c)
	}
	honest = new(bn256.G1).ScalarMult(ring[0][1], r) // r*Y_1 == sk*D
	return &transaction.Transaction{Payloads: []transaction.AssetPayload{{Statement: st}}}, ring, sk, honest
}

// restate shifts a proof to claim v+delta: B' = B - delta*G keeps C[k] == v'*G + B' true.
func restate(b *bn256.G1, delta uint64) *bn256.G1 {
	return new(bn256.G1).Add(b, new(bn256.G1).Neg(new(bn256.G1).ScalarMult(crypto.G, new(big.Int).SetUint64(delta))))
}

func TestR23ReceiverProofAcceptsHonest(t *testing.T) {
	tx, ring, sk, b := synthetic_payment(123456)
	amount, payload, err := verify_received_proof(b, 123456, tx, ring, sk)
	if err != nil || amount != 123456 || payload != 0 {
		t.Fatalf("honest proof refused: amount %d payload %d err %v", amount, payload, err)
	}
}

// The mechanism: the restated proof opens the same commitment (the equation proof.Prove checks holds), but its
// blinder is not sk*D, so the receiver check refuses it with ErrProofNotBound.
func TestR23ReceiverProofRefusesRestated(t *testing.T) {
	tx, ring, sk, b := synthetic_payment(123456)
	const delta = 4200000
	forged := restate(b, delta)
	lhs := tx.Payloads[0].Statement.C[1].EncodeCompressed()
	rhs := new(bn256.G1).Add(new(bn256.G1).ScalarMult(crypto.G, big.NewInt(123456+delta)), forged).EncodeCompressed()
	if string(lhs) != string(rhs) {
		t.Fatal("premise: the restated proof must satisfy C[k] == v'*G + B'")
	}
	if _, _, err := verify_received_proof(forged, 123456+delta, tx, ring, sk); err != ErrProofNotBound {
		t.Fatalf("restated proof: got %v, want ErrProofNotBound", err)
	}
	// a wrong amount with the honest blinder opens nothing
	if _, _, err := verify_received_proof(b, 123457, tx, ring, sk); err != ErrProofNoMatch {
		t.Fatalf("wrong amount: got %v, want ErrProofNoMatch", err)
	}
	// a wallet that is not in the ring cannot judge the proof
	if _, _, err := verify_received_proof(b, 123456, tx, ring, crypto.RandomScalar()); err != ErrProofNotForThisWallet {
		t.Fatalf("foreign wallet: got %v, want ErrProofNotForThisWallet", err)
	}
}

// The binding is per statement: an honest blinder for payload 0 must not authenticate payload 1 with another D.
func TestR23ReceiverProofBindsToStatementD(t *testing.T) {
	tx, ring, sk, b := synthetic_payment(77)
	tx.Payloads[0].Statement.D = new(bn256.G1).ScalarMult(crypto.G, crypto.RandomScalar())
	if _, _, err := verify_received_proof(b, 77, tx, ring, sk); err != ErrProofNotBound {
		t.Fatalf("D swapped: got %v, want ErrProofNotBound", err)
	}
}

// Real mainnet-format fixture (the proof/ Test_Prove vector): parsing works end to end through the public entry
// point, and a wallet that is not the receiver gets ErrProofNotForThisWallet rather than a false "valid".
func TestR23ReceiverProofFixture(t *testing.T) {
	const genuine = "deroproof1qyzlkv8x5cp7tgh3eeqjuu6nenaf0vfjcpm3fl784tkaa6tqpz2jsqdzvfyyskpq0kjaju7h2lw6h48g7fjsmgamxex0szh65f59tk7k82g3f39yt46ky4j4rgqqrp4q0wqa3c"
	ring := [][]string{{
		"deto1qyx7qyvrtrhvaszeej487k2g689fav7h38ay37fja9qf40ycgl0m2qg8ap2y9",
		"deto1qyre7td6x9r88y4cavdgpv6k7lvx6j39lfsx420hpvh3ydpcrtxrxqg8v8e3z",
		"deto1qysmp3ws28pkvas04cenrgmcjth8cavhd4z0x3xf0x0sl4033vlm6qgwhjz05",
		"deto1qypytjjcdzuqq05flnnlvcvja87672g0444rywvqvfq7szyv63ly7qgrkv0xg",
	}}
	const tx = "01000003519b9e874a9dd7fcbfb7802268123dcf970c336891101a3a0705855b72b9eb08c80100000000000000000000000000000000000000000000000000000000000000000000f394d06566a81b024fd8624b4c8592f8b9344e58f227261eb08d821bd190b4ac9c7df0660038ddcf881602a14fe5ad8eebff83d3ce3541a1f232fe61acf71109e417160936863e8c0597c798b73ef08e76b8eeebcaf20260ba91fcdef5f626361f824dc6197b02c599d4511c624a933226d8fccc125611ec80d8ad5acea4baf2f1c77e4c5525d9859b40f43daaf3d4e4450203d80419dcb026b9adbd7d6912284ee9ce20f3721076947f16e1faefd9b8c35116f4cf0044ead0a12fda3f3bcf2ed91627b922c02c10d112df9e782d3750cda151f6ba2ebe6495065141f32800894566011198c4055458005a31d3e285037446ba14bac54420bcab87cbebeaccab1f158b011e90132b7310e6c866e348cab68d21bad1d9f811b4d667a1e40bdef1a19259d3000b972ae06da958658b12ca4a45c2c6ea50d305be86f7e979fc962c687eb012f401a2c4bf0beb6c713343b94d65ee6d937660480daf670ab5b0ed421a9103e8a25119c836dd799600e67e4ec66ef680833398a99b16956aed2ee5bd9e6c8e68009a01145636e5e448d6c8ab902db394aa9c5aeee92dd150e1150d5b8f6674f330c279010912df27232ae126525a130ed8a9b4dee62eb57ce1d8a42ae9bcef867b10ce94012f94aa78846fcdda504243f83f3122aee5dc38dd32fa2a90224b3a40b4cf79c301129028709e39591c55e6e477a36cc26dc2efd7183fb59f51635dbd114dfed9d5010d66f31b781fa181c2114600ee1f03d55439355265700fb9d35ac684a19db398001e12558cc17e59fb85fb825481dee6fef3612c043bb38ca4833183da5381364600077a99d4d2df2f06067359f178a40f98a3e0943309c5ce3ce5398b9909174254012aa49cfc78ebec51c00e7824db0d8d41ef43fbb0396824d2c31b7db64124cc61000a8b51bd6c94a502f7aea3e5001f00d76b165ad580e48f8aa72813da8240286e00055f3480aa7cdb68a20d4b1e567d42389b44cf4e345da9e5a5655a80418695bc012c8f1e1ef8af646b4fb08afaeb3febde17c4c0d04b30dfd22d96a32ced9c9439010c40484e1547d307ad56b79bb7450e4eaaed7ed79bd5392dffd7449043f8783a0015104264f8d80356176ca6fdf4777e4ebc8edcbab50f8b6c366ac75ebd6bb5c701078d55053d2d41f21f51d5e617f282ba9dfa2576f0231048dd73998ceaa699fd0105821b61addd6935c7d80e65c706f0f2aa2d73ad22c5548c9c8b92cd82689dc40115f576c413a37014b9ee5377b121c69ad6e0f00f2b4f6c99d1f68b00a5d923370119b29fe6e9cf35f1344e24d52ee1fdb6521de3176f3d2b2a2b9327ae6e6cfbb10017198369a6ff180253700361c40e7f378c8e7ead6e04f01dbf5b4c47e7e1e4ff001abaf84628764eccbc5d0f66dc0a99505bb0e598362c45312470526afad11caf00242c6a902c564b3b363eb4ae08f643f18571779428358bfbdaf9856b0ebf229f0100000000000000000000000000000000000000000000000000000000000000001b7a78b6f573d4ac5d3a8d7d10dafac0dbc92604474417b29d40448d9fbc821d0fe3f73da41b27752d5db0658fcc0bff7da21112417ac719e491fdd43c8e5d0b07bcca22c27367a276e6a4e0cfb1bfbc772842898356ad4723101d4ada5137f409bb3b290d7519da3af15feb09e183e2be809690099551f1cb984deb1295b7611dd0cfd9000482314a388512d278fc22b2f6e3fc6e95023b4bd228e22626b7440119fa2c6f45a33b008ef5b23a5522ebbf0bf5f26d8263613a7f9b5ad9a192357600107a023453f7f79f413756dfba0096ae5d13158bbbb147089a020e819ef6640728acf01c811b967d1a14d767ac20088c5ca1613aa5d94ebe7fe2840b6431d8d002137dae183071d12cd9fb14c4b4738ef750ff514ce26257d1245eaedfea625516bfcb075a33a8910dc4e40742bfaa70d95591711e9db33d0db0be06cc819817072c22a9c81f4369f68bb1ef71c7f7458671d647caef18b30cca91da4f1b201d082a03306b4a07d1f0e1a8cc8844038fc524201a6c3a346a971203fd45458d292987d44049eecdac25c5622465a8d683a43621612d2fb283724b17a7bfa3bad2266a6fb1cf669eef21c90e24e85d6ab48e8b237355e964407dde00d65fb442dd210ce0378349f533c0e8ab65293de5319e246a044ed22b1e6db28add1508dd6f0da22954eea8a431b211a8b54147e32fec6593f9fb731389f62f94d5047e0f3301216576c71a79629bc3879325280e216d59cf7e6ff2d6a0babe418f8f2ed603ce010e16785f8c855043221ed5a603d4ed4e8e90059669543738ceb2a04dc996079c01264e9beaf4bb82e1b8f47bb0c239167064001e306eeef2b5495ec42754806b65012357f738543b13594ff081a070dbc0575645ac5ce8e0f89d3afdeb3d49e9ddae012a17d5095b9cef08f6eee2ce733dbf2cfcdb8c23e39410ed973e68cf8505266d00280c52b45752dd12ba84499618898111a8f9b19f2b76c06917e57eef221f3387011cc3360b478d144118a82a3c4391814f34aac2fb0f2d043394304bed179689e501292ca5631820f5f465242b4cc517f06c153c176a43f77daca463b7e2d3e2d7ba001aa0b2c90c3172cd2556137d78748f47924432449210d8b2f5e27adb6210bc77012c92a12526a5b0b1ef60994eb4d08e9bb5a3ea330d417838a52ad8636d37fa9e00131153c9affeefd6b98ecb6a80f5e6ea97417376030325182c064e12dd353c32011f4e25c49eea09adaa46d56642e2ea0afced2d75036acd3839435863f1ec3bf1002e19fe8456a7236c8fb77a15f87164debaad865e85c3468152a5deaffde3da6a01"
	w := &Wallet_Memory{account: &Account{Keys: Generate_Keys_From_Seed(crypto.RandomScalarBNRed())}}
	if _, err := w.VerifyReceivedPaymentProof(genuine, tx, ring); err != ErrProofNotForThisWallet {
		t.Fatalf("fixture with a foreign wallet: got %v, want ErrProofNotForThisWallet", err)
	}
	if _, err := w.VerifyReceivedPaymentProof("dero1qyx7qyvrtrhvaszeej487k2g689fav7h38ay37fja9qf40ycgl0m2qg8ap2y9", tx, ring); err == nil {
		t.Fatal("a plain address was accepted as a proof")
	}
	_ = rpc.RPC_VALUE_TRANSFER
}

// r23 merge: the proof generator's own blinder construction, B = C[k] - (value+burn)*G with amount = value+burn
// (daemon_communication.go), must verify for burn = 0 and burn > 0, and the authenticated amount is the received value.
// A restated proof of a burn transfer is still refused.
func TestR23ReceiverProofWithBurn(t *testing.T) {
	for _, burn := range []uint64{0, 7, 250000} {
		const value = 1000
		tx, ring, sk, _ := synthetic_payment(value)
		tx.Payloads[0].BurnValue = burn
		stated := uint64(value) + burn
		b := new(bn256.G1).Add(tx.Payloads[0].Statement.C[1], new(bn256.G1).Neg(new(bn256.G1).ScalarMult(crypto.G, new(big.Int).SetUint64(stated))))
		amount, _, err := verify_received_proof(b, stated, tx, ring, sk)
		if err != nil || amount != value {
			t.Fatalf("burn %d: honest wallet-built proof gave amount %d err %v (want %d, nil)", burn, amount, err, value)
		}
		if _, _, err := verify_received_proof(restate(b, 5000), stated+5000, tx, ring, sk); err != ErrProofNotBound {
			t.Fatalf("burn %d: restated proof got %v, want ErrProofNotBound", burn, err)
		}
	}
}
