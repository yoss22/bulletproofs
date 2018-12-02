package bulletproofs

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"
)

func MustDecode(h string) []byte {
	result, err := hex.DecodeString(h)
	if err != nil {
		panic("failed to parse hex string")
	}

	return result
}

func TestConstants(t *testing.T) {
	expectedC := MustDecode("0a2d2ba93507f1df233770c2a797962cc61f6d15da14ecd47d8d27ae1cd5f852")
	expectedD := MustDecode("851695d49a83f8ef919bb86153cbcb16630fb68aed0a766a3ec693d68e6afa40")

	if bytes.Compare(sqrtMinusThree.Bytes(), expectedC) != 0 {
		t.Errorf("TestConstants c wrong result\n"+
			"got: %v\nwant: %v", sqrtMinusThree.Bytes(), expectedC)
	}

	if bytes.Compare(sqrtMinusThreeSubOneOverTwo.Bytes(), expectedD) != 0 {
		t.Errorf("TestConstants d wrong result\n"+
			"got: %v\nwant: %v", sqrtMinusThreeSubOneOverTwo.Bytes(), expectedD)
	}
}

func TestHashToCurve(t *testing.T) {
	tests := []struct {
		fieldElement int64
		x            string
		y            string
	}{
		{
			1,
			"edd1fd3e327ce90cc7a3542614289aee9682003e9cf7dcc9cf2ca9743be5aa0c",
			"0225f529ee75acafccfc456026c5e46bf80237a33924655a16f90e88085ed52a",
		},
		{
			-1,
			"edd1fd3e327ce90cc7a3542614289aee9682003e9cf7dcc9cf2ca9743be5aa0c",
			"fdda0ad6118a53503303ba9fd93a1b9407fdc85cc6db9aa5e906f176f7a12705",
		},
		{
			2,
			"2c5cdc9c338152fa85de92cb1bee9907765a922e4f037cce14ecdbf22f78fe15",
			"567160696818286b72f01a3e5e8caca736249160c7ded69dd51913c303a2fa97",
		},
		{
			-2,
			"2c5cdc9c338152fa85de92cb1bee9907765a922e4f037cce14ecdbf22f78fe15",
			"a98e9f9697e7d7948d0fe5c1a1735358c9db6e9f382129622ae6ec3bfc5d0198",
		},
		{
			3,
			"531f7239aebc780e179fbf8d412a1b01511f0abce0c461518b38db84cc2467f3",
			"82387d45ec7bd5cc61fcb9df41cddd7b217d81143577dc8f23de356a7e97704e",
		},
		{
			-3,
			"531f7239aebc780e179fbf8d412a1b01511f0abce0c461518b38db84cc2467f3",
			"7dc782ba13842a339e034620be322284de827eebca882370dc21ca9481688be1",
		},
		{
			4,
			"2c5cdc9c338152fa85de92cb1bee9907765a922e4f037cce14ecdbf22f78fe15",
			"567160696818286b72f01a3e5e8caca736249160c7ded69dd51913c303a2fa97",
		},
		{
			-4,
			"2c5cdc9c338152fa85de92cb1bee9907765a922e4f037cce14ecdbf22f78fe15",
			"a98e9f9697e7d7948d0fe5c1a1735358c9db6e9f382129622ae6ec3bfc5d0198",
		},
		{
			5,
			"5e5936b181db0b658e33a8c61aa687dd31d11e1585e356646b4c2071cde7e942",
			"88bb5332a8e0565478d4f60c0cd979ec938558f2cac112167c387a56e3a6d5f3",
		},
		{
			-5,
			"5e5936b181db0b658e33a8c61aa687dd31d11e1585e356646b4c2071cde7e942",
			"7744accd571fa9ab872b09f3f32686136c7aa70d353eede983c785a81c59263c",
		},
		{
			6,
			"657d438ffac34a50463fd07c3f09f3204c98e8ed6927e330c0c7735f76d32f6d",
			"577c2b11caca2f6fd60bcaf03e7cebe95da6e1f4bb557f122a39733181df897f",
		},
		{
			-6,
			"657d438ffac34a50463fd07c3f09f3204c98e8ed6927e330c0c7735f76d32f6d",
			"a883d4ee3535d09029f4350fc1831416a2591e0b44aa80edd5c68ccd7e2072b0",
		},
		{
			7,
			"be0bc11b2bc639cbc28f72a8d07c21ccbc06cfa74c2ff25e630c974023128eab",
			"6f062fc875148197d10375c3cc3fadb620277e9c00579c55eddd7f95e95604db",
		},
		{
			-7,
			"be0bc11b2bc639cbc28f72a8d07c21ccbc06cfa74c2ff25e630c974023128eab",
			"90f9d0378aeb7e682efc8a3c33c05249dfd88163ffa863aa1222806916a9f754",
		},
		{
			8,
			"edd1fd3e327ce90cc7a3542614289aee9682003e9cf7dcc9cf2ca9743be5aa0c",
			"fdda0ad6118a53503303ba9fd93a1b9407fdc85cc6db9aa5e906f176f7a12705",
		},
		{
			-8,
			"edd1fd3e327ce90cc7a3542614289aee9682003e9cf7dcc9cf2ca9743be5aa0c",
			"0225f529ee75acafccfc456026c5e46bf80237a33924655a16f90e88085ed52a",
		},
		{
			9,
			"aee172d4ce7c5010db20a88f469598c1d7f7926fabb85cb5339f140387e6b494",
			"380659804de81b35098c7190e3380f9d95b2ed6c6c869e85c772bc5a7bc3d9d5",
		},
		{
			-9,
			"aee172d4ce7c5010db20a88f469598c1d7f7926fabb85cb5339f140387e6b494",
			"c7f9a67fb217e4caf6738e6f1cc7f0626a4d12939379617a388d43a4843c225a",
		},
		{
			10,
			"c28f5c28f5c28f5c28f5c28f5c28f5c28f5c28f5c28f5c28f5c28f5b6666635a",
			"0c4da8401b2cf5be4604e6ecf92b2780063a5351e294bf65bb2f8b6100902db7",
		},
		{
			-10,
			"c28f5c28f5c28f5c28f5c28f5c28f5c28f5c28f5c28f5c28f5c28f5b6666635a",
			"f3b257bfe4d30a41b9fb191306d4d87ff9c5acae1d6b409a44d0749dff6fce78",
		},
		{
			11,
			"ecf56be69c8fde26152832c6e043b3d5af9a723f789854a0cb1b810de2614ece",
			"66127ae4e4c17a7560a727e6ffd2ea7faed99088bec465c6bde5679137ed5572",
		},
		{
			-11,
			"ecf56be69c8fde26152832c6e043b3d5af9a723f789854a0cb1b810de2614ece",
			"99ed851b1b3e858a9f58d819002d158051266f77413b9a39421a986dc812a6bd",
		},
		{
			12,
			"ba72860f10fcd14223f71e3c228deb9ac46c5ff590b884e5cc60d51e0629d16e",
			"67999f315a74ada3526832cf76b9fec3a348cc9733c3aa6702bd25167814f635",
		},
		{
			-12,
			"ba72860f10fcd14223f71e3c228deb9ac46c5ff590b884e5cc60d51e0629d16e",
			"986660cea58b525cad97cd308946013c5cb73368cc3c5598fd42dae887eb05fa",
		},
		{
			13,
			"92ef5657dba51cc7f3e1b442a6a0916b8ce030792ef5657dba51cc7eab2beb65",
			"782c65d23f1e0eb29179a994e5e8ff805a0d50d9deeaed90cec96ca5973e2ad3",
		},
		{
			-13,
			"92ef5657dba51cc7f3e1b442a6a0916b8ce030792ef5657dba51cc7eab2beb65",
			"87d39a2dc0e1f14d6e86566b1a17007fa5f2af262115126f3136935968c1d15c",
		},
		{
			14,
			"9468ad22f921fc788de3f1b0586c58eb5e6f0270e950b6027ada90d9d71ae323",
			"922a0c6a9ccc31d9c3bf87fd8838173935fe393fa64dfdec29f2846d12918d86",
		},
		{
			-14,
			"9468ad22f921fc788de3f1b0586c58eb5e6f0270e950b6027ada90d9d71ae323",
			"6dd5f3956333ce263c40780277c7e8c6ca01c6c059b20213d60d7b91ed6e6ea9",
		},
		{
			15,
			"76ddc7f5e029e59e22b0e54fa811db945a209c4f5e912ca28b4da6a74c1e00a2",
			"1e8f516c91c2043750f6e24e8c2cf202acf68291bf8b66ebf7335b62ec2c88fe",
		},
		{
			-15,
			"76ddc7f5e029e59e22b0e54fa811db945a209c4f5e912ca28b4da6a74c1e00a2",
			"e170ae936e3dfbc8af091db173d30dfd53097d6e4074991408cca49c13d37331",
		},
		{
			16,
			"f75763bc2907e79b125e33c39a027f480f8c64092153432f967bc2b11d1f5cf0",
			"b4a8edc636391b399bc219c03d033128dbcd463ed2506394061b87a59e510235",
		},
		{
			-16,
			"f75763bc2907e79b125e33c39a027f480f8c64092153432f967bc2b11d1f5cf0",
			"4b571239c9c6e4c6643de63fc2fcced72432b9c12daf9c6bf9e4785961aef9fa",
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		x, _ := new(big.Int).SetString(test.x, 16)
		y, _ := new(big.Int).SetString(test.y, 16)
		expected := &Point{x, y}

		fieldElement := big.NewInt(test.fieldElement)

		// Normalise the field element if necessary.
		if test.fieldElement < 0 {
			fieldElement = fieldElement.Add(fieldElement, curve.P)
		}

		result := EncodeFieldElementToCurve(fieldElement)

		if !result.Equals(expected) {
			t.Errorf("TestHashToCurve #%d wrong result\n"+
				"got:  %v\nwant: %v", i, result, expected)
			continue
		}
	}
}

func TestCreateGenerators(t *testing.T) {
	G := GeneratorsCreate(3)

	expectedX := MustDecode("b34d5fa6b8f3d13849ce5191b7f67618fe5bd12a88b20eac338945667fb33056")
	expectedY := MustDecode("45764c5127badee8be74c88f9b55fcdd466947217f9985a89e33d492d331026e")
	expected := &Point{
		new(big.Int).SetBytes(expectedX),
		new(big.Int).SetBytes(expectedY),
	}

	if !G[0].Equals(expected) {
		t.Errorf("TestHashToCurve wrong result\n"+
			"got: %v\nwant: %v", G[0], expected)
	}

	expectedX2 := MustDecode("628615169242109e9e64d4cb2881609c24b989512ad901aeff75649c375dbd79")
	expectedY2 := MustDecode("a2a4ab84fc9fc5172a9d8bd68d1f01304d0193bfc1f4f101f650dcc67460e610")
	expected2 := &Point{
		new(big.Int).SetBytes(expectedX2),
		new(big.Int).SetBytes(expectedY2),
	}

	if !G[1].Equals(expected2) {
		t.Errorf("TestHashToCurve wrong result\n"+
			"got: %v\nwant: %v", G[1], expected2)
	}

	expectedX3 := MustDecode("ede06e075e79d0f77b033eb9a921a45b99f39beefea037a21fe9d74f958b10e2")
	expectedY3 := MustDecode("b6bca187e838bad2783bb977c1eb184463b14a5cab7a588dc45abe4d98ba40e4")
	expected3 := &Point{
		new(big.Int).SetBytes(expectedX3),
		new(big.Int).SetBytes(expectedY3),
	}

	if !G[2].Equals(expected3) {
		t.Errorf("TestHashToCurve wrong result\n"+
			"got: %v\nwant: %v", G[2], expected3)
	}
}
