package bulletproofs

import (
	"bytes"
	"math/big"
	"testing"
)

func decompressPointFromHex(s string) *Point {
	point := new(Point)
	if err := point.Read(bytes.NewReader(MustDecode(s))); err != nil {
		panic(err)
	}
	return point
}

// mustDecode32Bytes reads exactly 32 bytes from a hex encoded string.
func mustDecode32Bytes(h string) [32]byte {
	var buf [32]byte
	s := MustDecode(h)
	if len(s) != 32 {
		panic("expected 32 bytes of input")
	}
	copy(buf[:], s)
	return buf
}

func TestComputePowersOfChallenge(t *testing.T) {
	tests := []struct {
		exponent int64
		powers   []int64
	}{
		{
			0,
			[]int64{1, 0, 0},
		},
		{
			1,
			[]int64{1, 1, 1},
		},
		{
			2,
			[]int64{1, 2, 4, 8},
		},
	}

	for i, test := range tests {
		powers := powers(big.NewInt(test.exponent), len(test.powers))

		for p := range powers {
			expected := big.NewInt(test.powers[p])
			if powers[p].Cmp(expected) != 0 {
				t.Errorf("TestComputePowersOfChallenge #%d wrong result\n"+
					"got: %v\nwant: %v", i, powers[p], expected)
			}
		}
	}
}

func TestBitVector(t *testing.T) {
	one := big.NewInt(1)
	zero := big.NewInt(0)

	a := big.NewInt(13)
	// 13 = 1 * 2^0 + 0 * 2^1 + 1 * 2^2 + 1 * 2^3
	expected := []*big.Int{one, zero, one, one}

	actual := bitVector(a, 4)
	for i := 0; i < len(actual); i++ {
		if actual[i].Cmp(expected[i]) != 0 {
			t.Errorf("TestBitVector #%d wrong result\n"+
				"got: %v\nwant: %v", i, actual[i], expected[i])
		}
	}

	// We also expect actual · 2^n = a, so check that too.
	twoPowers := powers(big.NewInt(2), 4)
	dot := Dot(actual, twoPowers)
	if dot.Cmp(a) != 0 {
		t.Errorf("TestBitVector wrong result\n"+
			"got: %v\nwant: %v", dot, a)
	}
}

func TestComputeAR(t *testing.T) {
	one := big.NewInt(1)
	negone := new(big.Int).Add(curve.N, big.NewInt(-1))
	zero := big.NewInt(0)

	// The bit-vector representation of the decimal value 13.
	// 13 = 1 * 2^0 + 0 * 2^1 + 1 * 2^2 + 1 * 2^3
	aL := []*big.Int{one, zero, one, one}
	expected := []*big.Int{zero, negone, zero, zero}

	actual := computeAR(aL)
	for i := 0; i < len(actual); i++ {
		if actual[i].Cmp(expected[i]) != 0 {
			t.Errorf("TestComputeAR #%d wrong result\n"+
				"got: %v\nwant: %v", i, actual[i], expected[i])
		}
	}

	// Also check that a_L ○ a_R = 0.
	zeroN := []*big.Int{zero, zero, zero, zero}
	product := Hadamard(aL, actual)
	for i := 0; i < len(product); i++ {
		if product[i].Cmp(zeroN[i]) != 0 {
			t.Errorf("TestComputeAR #%d wrong result\n"+
				"got: %v\nwant: %v", i, product[i], zeroN[i])
		}
	}
}

// TestRangeProofVerifySmallRange creates a range proof for a small value and
// checks it verifies correctly.
func TestRangeProofVerifySmallRange(t *testing.T) {
	v := big.NewInt(13) // the scalar we want to generate a range proof for
	gamma := big.NewInt(10)
	prover := NewProver(4)

	// V = γH + vG.
	V := commit(gamma, prover.BlindingGenerator, v, prover.ValueGenerator)

	proof, err := prover.CreateRangeProof(V, v, gamma, [32]byte{}, [16]byte{})
	if err != nil {
		t.Errorf("failed to create range proof: %v", err)
	}

	if !prover.Verify(V, proof) {
		t.Error("Expected valid proof")
	}
}

// TestRangeProofVerifySmallNumber creates a range proof for a small value and
// checks it verifies correctly in a 64-bit range.
func TestRangeProofVerifySmallNumber(t *testing.T) {
	v := big.NewInt(13) // the scalar we want to generate a range proof for
	gamma, _ := new(big.Int).SetString("0c20e866a047cea6c61c820d1db685392c10047c7e861e34234caccef2844ded", 16)

	prover := NewProver(64)

	// V = γH + vG.
	V := commit(gamma, prover.BlindingGenerator, v, prover.ValueGenerator)

	proof, err := prover.CreateRangeProof(V, v, gamma, [32]byte{}, [16]byte{})
	if err != nil {
		t.Errorf("failed to create range proof: %v", err)
	}

	if !prover.Verify(V, proof) {
		t.Error("Expected valid proof")
	}
}

// TestRangeProofVerifyLarge creates a range proof for a realistic sized value.
func TestRangeProofVerifyLarge(t *testing.T) {
	serialisedRangeProof := MustDecode("07cebfaa75fb4b0cf626c1400d7a36ebcf3810e8e92c45acab722fbbfbadb7ecb9d8959c75f2046401b6e7bec763a759e3f994540ec3bc7abe67755d70a53ef10aabd7c1ee6d60c83c97750ebf05bac393ff1311dbd80609940315969ee0cc3dd91116e73c87f6dda42915254e6b3ab723f282bfd98a6e50bfe4a3f6e0c2b883045e512ead41d8e5740b422ddd6754b30343aa9f3b7e2bcfcf9116821c46b427128a378093f23adcf348ae18f0abca564253740103d12463358e6a34f393bac11f158e311f609fdea1ac2decf95fb94a5802e2dcbafc10371f5ce0bf8a678e2e55aeba682c6dc8aad0e259066b24850207ddeee75373d6c9964ac0e8df0d2113f9a0b7dbd7e0c24db713941d95567ef81d277331622d10bfefe7fc8488b39cd729173916675b667b697317a2255b7e00af83b7e833ed3880946f62849f8502d97308a36e1a5848b70241240f9ce57cfedd0d0dfd0b0aa937ab4934378af72d8fb07900f5f3184e39bac8161df661e33656124581806e7835969009b5e2295cce651c09bf0f645c86f80236a30819f9c4bbcc81132939ac10a2e47ea37f9adeff3541672cb4fa68a608db9395b291728369c8e89f442323cac7d7d53522312d15c0def7475e26c0fc99ceaa86385cf722fa07073e79fd02e7f1ff5e8e8545ef0e2ba7c3104eaacd6e564877928448b5e0b4a30fbbabc977c8bd0bd5e579a9d4aa86ea09ef55e8a59e404f98540bfac3131ff21db44c62ef277dcf70cc92c324a1adb5bc8d3617dfa3b595514a01da977a7164662534ab33aa061c87af55245ab2384cae598c5c5c27506c457b41b8e5a488ddc33acbe5355a246656bb0934fc3050c53b35e05e797caa855bd375b78edff1caac2e5b8eb74b9a56c5ea3b7d718ecf40972fcf8990131eebc77aabb2289b7b248682408faf0d4516cfff15ac17f669994a")
	serialisedCommitment := MustDecode("098ae3f5b358d56249aef94ff714ccd4e9975bd5c79a56e003b60c04c1cabcdd57")

	proof := new(BulletProof)
	err := proof.Read(bytes.NewReader(serialisedRangeProof))
	if err != nil {
		t.Error("Failed to deserialize proof")
	}

	V := new(Point)
	if err := V.Read(bytes.NewReader(serialisedCommitment)); err != nil {
		t.Error("Failed to deserialize commitment")
	}

	verifier := NewProver(64)
	if !verifier.Verify(V, *proof) {
		t.Error("Expected valid proof")
	}
}

// TestCreateRangeProof creates a range proof and checks it against a known good
// result.
func TestCreateRangeProof(t *testing.T) {
	V := decompressPointFromHex("098ae3f5b358d56249aef94ff714ccd4e9975bd5c79a56e003b60c04c1cabcdd57")

	blind := mustDecode32Bytes("193c28a9edf6f05f67e7bfb389aea21ad2fc8b5d497dd5763aa5f5cdfda5f147")
	gamma := new(big.Int).SetBytes(blind[:])

	nonce := mustDecode32Bytes("be59e9aab76b9abba0a2993166536d1f13ed6d12281cfcb700c1722daf4ad088")

	message := [16]byte{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}

	prover := NewProver(64)

	proof, err := prover.CreateRangeProof(V, big.NewInt(5), gamma, nonce, message)
	if err != nil {
		t.Errorf("failed to create range proof: %v", err)
	}

	if !prover.Verify(V, proof) {
		t.Error("Expected valid proof")
	}

	deserialised := new(BulletProof)
	err = deserialised.Read(bytes.NewReader(proof.Bytes()))
	if err != nil {
		t.Error("Failed to deserialize proof")
	}

	if !prover.Verify(V, *deserialised) {
		t.Error("Expected valid proof")
	}

	expectedProof := MustDecode("07cebfaa75fb4b0cf626c1400d7a36ebcf3810e8e92c45acab722fbbfbadb7ecb9d8959c75f2046401b6e7bec763a759e3f994540ec3bc7abe67755d70a53ef10aabd7c1ee6d60c83c97750ebf05bac393ff1311dbd80609940315969ee0cc3dd91116e73c87f6dda42915254e6b3ab723f282bfd98a6e50bfe4a3f6e0c2b883045e512ead41d8e5740b422ddd6754b30343aa9f3b7e2bcfcf9116821c46b427128a378093f23adcf348ae18f0abca564253740103d12463358e6a34f393bac11f158e311f609fdea1ac2decf95fb94a5802e2dcbafc10371f5ce0bf8a678e2e55aeba682c6dc8aad0e259066b24850207ddeee75373d6c9964ac0e8df0d2113f9a0b7dbd7e0c24db713941d95567ef81d277331622d10bfefe7fc8488b39cd729173916675b667b697317a2255b7e00af83b7e833ed3880946f62849f8502d97308a36e1a5848b70241240f9ce57cfedd0d0dfd0b0aa937ab4934378af72d8fb07900f5f3184e39bac8161df661e33656124581806e7835969009b5e2295cce651c09bf0f645c86f80236a30819f9c4bbcc81132939ac10a2e47ea37f9adeff3541672cb4fa68a608db9395b291728369c8e89f442323cac7d7d53522312d15c0def7475e26c0fc99ceaa86385cf722fa07073e79fd02e7f1ff5e8e8545ef0e2ba7c3104eaacd6e564877928448b5e0b4a30fbbabc977c8bd0bd5e579a9d4aa86ea09ef55e8a59e404f98540bfac3131ff21db44c62ef277dcf70cc92c324a1adb5bc8d3617dfa3b595514a01da977a7164662534ab33aa061c87af55245ab2384cae598c5c5c27506c457b41b8e5a488ddc33acbe5355a246656bb0934fc3050c53b35e05e797caa855bd375b78edff1caac2e5b8eb74b9a56c5ea3b7d718ecf40972fcf8990131eebc77aabb2289b7b248682408faf0d4516cfff15ac17f669994a")

	if bytes.Compare(expectedProof, proof.Bytes()) != 0 {
		t.Error("Proof doesn't match golden")
	}
}

func TestUpdateCommit(t *testing.T) {
	zeros := mustDecode32Bytes("00e96c16889c4950e8f515788fa02aad13df42fc39a932ca94ed615f8f5592ad")
	lx := mustDecode32Bytes("abd7c1ee6d60c83c97750ebf05bac393ff1311dbd80609940315969ee0cc3dd9")
	ly := mustDecode32Bytes("2a398e6553103f34efc85b4c9217cca19bcce985f5e7739443a6e72dafacbe6f")
	l := &Point{
		X: new(big.Int).SetBytes(lx[:]),
		Y: new(big.Int).SetBytes(ly[:])}
	rx := mustDecode32Bytes("1116e73c87f6dda42915254e6b3ab723f282bfd98a6e50bfe4a3f6e0c2b88304")
	ry := mustDecode32Bytes("a3f62a70ae256efa3deae8703ab6814d8faadfb350378dd4c7cfc9a7b82c8bda")
	r := &Point{
		X: new(big.Int).SetBytes(rx[:]),
		Y: new(big.Int).SetBytes(ry[:])}

	expected := mustDecode32Bytes("3f759d46ace638016492b0c33ba3ccd43954965be581012f31b0696d27af6ea2")
	actual, _ := updateCommit(zeros, l, r)

	if bytes.Compare(expected[:], actual[:]) == 0 {
		t.Errorf("TestUpdateCommit wrong result got %032x want %032x", actual, expected)
	}
}

// TestRangeProofVerifyTestnet3 takes a range proof from testnet 3 and verifies
// it.
func TestRangeProofVerifyTestnet3(t *testing.T) {
	V := decompressPointFromHex("08e33c2cc6fc36e38dc95e1d6378f0746cac15e5b16cf40572c99e767f9c433b47")
	serialisedRangeProof := MustDecode("71fcd0986485dba915650a01e4606afb993c6b9b0980989e1edde0549403400fb8bf95dbb6077ff30c3d9096cbafe411e3544f7d76e69e1afbc0ac6a184b274e052e0b8382368dcea0f71cbb0def7e8fc934e5156fb5bd53d03e1664bce655f737dc550b54d56bf1ae6e1a05c577a62e1793805149e57147b1d51bf4c1e4358860ead3786c23ed4aa5f0c12d6b13d02ff7c0b2ef34e90807e4224c8b0ba9ef51607ec4258d09119a775c525fc8474321a83439263f6939f45c34c2aedb4fb41b5db1284f1fd038749d9f553803de841e8b2135fea42c4d746c01c9ada3c86d71c7ea7cfc6463932cc4c5a445086bd111d2630d94c8042607898b7939506108fb71cbd398e0fc5ed3e6e8a6898132dfd78fc141d36722a8c23c870d10038b3f4b685bce12d1e85fe222f8bd80372353522825dd80344b11172cba9b8a5d5e29671e270c67953812589b12a3d7bd89d9ac68368bdef76a32040058dae90a9e79fa3ffa012e099b9bade7cce98200cdb3d6dd8725cf2e46eb189b4802edd7e854682c707350d12a0ccad2a9ac351742f6600fe70bce872a1584cffaf4c8a2ff1b1e25e70d83a3c2df9863b838590cd5bfc87d8f641e880bacea91edad005498a756cb5583805c6262c564b6fba408a10ce7aac1726ed98fb5bc7b39285facb238f9ec0436f9ab83d36003d247280729ff9df1a38fd0c8539725e1ebca19eca244dd0bedbafdad3126b2ead60b44208105bb231d2c3909682424da06be8b1e3175b35cbd74cac04da907c2971475df0fb00a1bce853c062aa5c4df7e60a5e1595438a575476a2972d2f0c43567e7279f43fa362c1ddf454dbf23d7e7e000964febb83f5a01dc2dbc3ce1c1241ce74786338740f146a51239e9af29051e1311467cc4e35e232446a10e0bbcd16cf635b45804d8968e7c50b72946039feed4454c95e2d3d79e")

	proof := new(BulletProof)
	err := proof.Read(bytes.NewReader(serialisedRangeProof))
	if err != nil {
		t.Error("Failed to deserialize proof")
	}

	verifier := NewProver(64)
	if !verifier.Verify(V, *proof) {
		t.Error("Expected valid proof")
	}
}

// TestRangeProofVerifyTestnet32 takes a range proof from testnet 3 and verifies
// it.
func TestRangeProofVerifyTestnet32(t *testing.T) {
	V := decompressPointFromHex("08788774263bce7e1d800005a0c413fac30927db8a3b51feb0106235de877a8055")
	serialisedRangeProof := MustDecode("3ff00181a4f9f03495197521af5afb27239480a2da498b71328d059c2f062f5342ae8cd3010540506931f8f3a40d4ede24f1dbf0be5b989b911330fb4cbf120f0d4896808d1292c39bd2d53601b236523fca7e2f4e0078d57ae467f124dd1d67d45e918fd7f1fd99fc0bc0619fdb5063664dec67ec189adeb01868e114e89d4508dc14f2d318ccc2934d49bb892872bc2784845041898fd09dc4cb9982b9e3e290d75e1c79950fad5c4e934bf008ea439308b28ff5a5c592d011294cf188bdc99e8cc613ebaf51ed16eae6bd3f5a565d2ae9061f8164770ea98d15e05a63eb2141186bb19e54b07a3d396da29b8e5101f6aa76a3a0092153ddd49e27d8a5231841c5e813c7f310c3c443097d2640dd604cbeda5f8af8b4363c98b1d2c0940b89eff87d3f2758e7bf6698d6484657ebb750f3d7ac89055050241e358a1e99d16dc0b8a8a6a6b5a407d4de4086be31947bcfda1d42c5ccdbc70f1a7ed214e13033f8bf0118ad7de8df78f7dbb7ae4daf183047e1c9065cadfb2e9fc1e7481942edbd32619b3e9a619f85aa56d08e20fdad4ee338852aecd02733c5d8b8290d275563468f4443e43f64fddb0fc29ef209a0e65ebbdb2cc5572741fe9fd983d2c400dedd7e27273d8d2f9a1aff611d2ca994640b3d93b7bcd1c46730460658a2af9f2b97830b7be414d371ddbffaa6e2cbce0843120c985d2af1798eea5481a6a2a8b1bfdc90f9163c856cc96771613ada9ed3ccd7cec14034814b6924c85cf10b507a088835ba40d6bcb297b8cc060d41e736b8fb92bd68103218fcc11e09b73ef20074cf93c826dc28fada116908dbb4d83957dc0202c333cbfe5473c9c98e30abdd7803511b824ad1ae961bc61cc6c074110ed43a43b41c4c6189b5b49446c771d0482f456cbdfedb7e269e1ad48bc344a6b3025cc4b8f5282e3f5618bd93ccee412fb0")

	proof := new(BulletProof)
	err := proof.Read(bytes.NewReader(serialisedRangeProof))
	if err != nil {
		t.Error("Failed to deserialize proof")
	}

	verifier := NewProver(64)
	if !verifier.Verify(V, *proof) {
		t.Error("Expected valid proof")
	}
}

func TestSerializePoints(t *testing.T) {
	gx, _ := new(big.Int).SetString("fde99f907173c020c12abd7a69b7c0e3b6c470ce2e4f8a9d2d7941ba7fab0404", 16)
	gy, _ := new(big.Int).SetString("ee1a85649590ee2b6e4f452c59d97caef3be4a976456b56d641f6ef671aaa454", 16)

	hx, _ := new(big.Int).SetString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16)
	hy, _ := new(big.Int).SetString("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16)

	g := Point{X: gx, Y: gy}
	h := Point{X: hx, Y: hy}

	buf := SerializePoints([]*Point{&g, &h})

	points, _ := DeserializePoints(buf, 2)

	if !points[0].Equals(&g) {
		t.Errorf("TestSerializePoints wrong result got %v want %v", points[0], g)
	}

	if !points[1].Equals(&h) {
		t.Errorf("TestSerializePoints wrong result got %v want %v", points[1], h)
	}
}
