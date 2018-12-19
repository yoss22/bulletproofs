package bulletproofs

import (
	"bytes"
	"math/big"
	"testing"
)

func TestScalarMul(t *testing.T) {
	vec := []*big.Int{big.NewInt(1), big.NewInt(2)}

	actual := ScalarMul(vec, big.NewInt(2))

	expected := []*big.Int{big.NewInt(2), big.NewInt(4)}

	for i := range actual {
		if actual[i].Cmp(expected[i]) != 0 {
			t.Errorf("TestScalarMul wrong result\n"+
				"got: %v\nwant: %v", actual[i], expected[i])
		}
	}
}

func TestScalarMult(t *testing.T) {
	point := &Point{curve.Gx, curve.Gy}
	scalar := big.NewInt(2)

	expectedX, expectedY := curve.ScalarBaseMult(scalar.Bytes())

	actual := ScalarMulPoint(point, scalar)

	if actual.X.Cmp(expectedX) != 0 || actual.Y.Cmp(expectedY) != 0 {
		t.Errorf("TestScalarMult wrong result\n"+
			"got: %v\nwant: %v %v", actual, expectedX, expectedY)
	}
}

func TestDot(t *testing.T) {
	a := []*big.Int{big.NewInt(2), big.NewInt(3)}
	b := []*big.Int{big.NewInt(4), big.NewInt(5)}

	// a·b = 2×4 + 3×5 = 23
	actual := Dot(a, b)
	expected := big.NewInt(23)
	if actual.Cmp(expected) != 0 {
		t.Errorf("TestDot wrong result\n"+
			"got: %v\nwant: %v", actual, expected)
	}
}

func TestSub(t *testing.T) {
	a := []*big.Int{big.NewInt(2), big.NewInt(3)}
	b := []*big.Int{big.NewInt(4), big.NewInt(5)}
	c := []*big.Int{big.NewInt(2), big.NewInt(2)}

	// b-a = (4-2, 5-2) = (2, 2)
	actual := SubVectors(b, a)
	for i := 0; i < len(actual); i++ {
		if actual[i].Cmp(c[i]) != 0 {
			t.Errorf("TestSub #%d wrong result\n"+
				"got: %v\nwant: %v", i, actual[i], c[i])
		}
	}
}

func TestOnes(t *testing.T) {
	expected := []*big.Int{big.NewInt(1), big.NewInt(1), big.NewInt(1)}
	actual := Ones(3)

	for i := 0; i < len(actual); i++ {
		if actual[i].Cmp(expected[i]) != 0 {
			t.Errorf("TestOnes #%d wrong result\n"+
				"got: %v\nwant: %v", i, actual[i], expected[i])
		}
	}
}

func TestHadamard(t *testing.T) {
	a := []*big.Int{big.NewInt(2), big.NewInt(3)}
	b := []*big.Int{big.NewInt(4), big.NewInt(5)}
	c := []*big.Int{big.NewInt(8), big.NewInt(15)}

	// a ○ b = (2*4, 3*5) = (8, 15)
	actual := Hadamard(a, b)
	for i := 0; i < len(actual); i++ {
		if actual[i].Cmp(c[i]) != 0 {
			t.Errorf("TestHadamard #%d wrong result\n"+
				"got: %v\nwant: %v", i, actual[i], c[i])
		}
	}
}

func TestMul(t *testing.T) {
	expected := big.NewInt(30)
	actual := Mul(big.NewInt(5), big.NewInt(6))

	if actual.Cmp(expected) != 0 {
		t.Errorf("TestMul wrong result\n"+
			"got: %v\nwant: %v", actual, expected)
	}
}

func TestInverse(t *testing.T) {
	y := big.NewInt(3)
	expected := big.NewInt(1)
	actual := Mul(Inv(y), y)
	if actual.Cmp(expected) != 0 {
		t.Errorf("TestInverse wrong result\n"+
			"got: %v\nwant: %v", actual, expected)
	}
}

func TestNeg(t *testing.T) {
	expected := big.NewInt(1)
	actual := Sum(Neg(big.NewInt(4)), big.NewInt(5))

	if actual.Cmp(expected) != 0 {
		t.Errorf("TestNeg wrong result\n"+
			"got: %v\nwant: %v", actual, expected)
	}
}

func TestMul3(t *testing.T) {
	expected := big.NewInt(120)
	actual := Mul(big.NewInt(4), big.NewInt(5), big.NewInt(6))

	if actual.Cmp(expected) != 0 {
		t.Errorf("TestMul3 wrong result\n"+
			"got: %v\nwant: %v", actual, expected)
	}
}

func TestSum(t *testing.T) {
	expected := big.NewInt(15)

	a, b, c := big.NewInt(4), big.NewInt(5), big.NewInt(6)
	actual := Sum(a, b, c)

	if actual.Cmp(expected) != 0 {
		t.Errorf("TestSum wrong result\n"+
			"got: %v\nwant: %v", actual, expected)
	}
}

func TestGetB32(t *testing.T) {
	expected := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	actual := GetB32(big.NewInt(1))
	if !bytes.Equal(actual[:], expected) {
		t.Errorf("TestGetB32 wrong result\n"+
			"got: %v\nwant: %v", actual, expected)
	}
}

func TestGetB32_2(t *testing.T) {
	expected := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}
	actual := GetB32(big.NewInt(1 << (8 * 4)))
	if !bytes.Equal(actual[:], expected) {
		t.Errorf("TestGetB32_2 wrong result\n"+
			"got: %v\nwant: %v", actual, expected)
	}
}

// number is a randomly picked integer to use in the benchmarks.
var number, _ = new(big.Int).SetString("4d43fb380a3eca2d4c8a07546913c2e5879d7918a035205231e18051b8572020", 16)
var result *big.Int

func BenchmarkModSqrt(b *testing.B) {
	var r *big.Int
	for n := 0; n < b.N; n++ {
		r = ModSqrtOrig(number)
	}
	result = r
}

func BenchmarkModSqrtFast(b *testing.B) {
	var r *big.Int
	for n := 0; n < b.N; n++ {
		r = ModSqrtFast(number)
	}
	result = r
}
