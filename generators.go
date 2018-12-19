package bulletproofs

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"github.com/btcsuite/btcd/btcec"
	"math/big"
)

var (
	// prefix1 is the ascii string "1st generation: "
	prefix1, _ = hex.DecodeString("3173742067656e65726174696f6e3a20")

	// prefix2 is the ascii string "2nd generation: "
	prefix2, _ = hex.DecodeString("326e642067656e65726174696f6e3a20")

	// curve is secp256k1
	curve = btcec.S256()

	// sqrtMinusThree as a field element in secp256k1
	sqrtMinusThree = computeSqrtMinusThree()

	// sqrtMinusThreeSubOneOverTwo as a field element in secp256k1
	sqrtMinusThreeSubOneOverTwo = subOneOverTwo(sqrtMinusThree)
)

// newRFC6979 generates an ECDSA nonce deterministically according to RFC 6979.
func newRFC6979(hash []byte) ([]byte, []byte) {
	oneInitializer := []byte{0x01}

	// Step B
	v := bytes.Repeat(oneInitializer, 32)

	// Step C
	k := make([]byte, 32)

	// Step D
	k = mac(k, append(append(v, 0x00), hash...))

	// Step E
	v = mac(k, v)

	// Step F
	k = mac(k, append(append(v, 0x01), hash...))

	// Step G
	v = mac(k, v)

	return v, k
}

// update computes and returns the next values for V and K.
func update(v, k []byte) ([]byte, []byte) {
	// K = HMAC_K(V || 0x00)
	k = mac(k, append(v, 0x00))

	// V = HMAC_K(V)
	v = mac(k, v)

	return v, k
}

// generate returns a key from v, k and returns new values of v, k.
func generate(v, k []byte) ([]byte, []byte, []byte) {
	qlen := curve.Params().N.BitLen()

	// Step H1
	var t []byte

	// Step H2
	for len(t)*8 < qlen {
		// V = HMAC_K(V)
		v = mac(k, v)
		// T = T || V
		t = append(t, v...)
	}

	return t, v, k
}

// mac returns an HMAC of the given key and message.
func mac(k, m []byte) []byte {
	h := hmac.New(sha256.New, k)
	h.Write(m)
	return h.Sum(nil)
}

// computeSqrtMinusThree returns the field element a such that a*a = -3 mod p,
// where p is the order of the field secp256k1.
func computeSqrtMinusThree() *big.Int {
	curveOrder := curve.P
	curveOrderMinus3 := new(big.Int).Sub(curveOrder, new(big.Int).SetUint64(3))

	sqrt := new(big.Int)
	if sqrt.ModSqrt(curveOrderMinus3, curveOrder) == nil {
		panic("failed to find root")
	}

	return sqrt
}

// subOneOverTwo computes (c - 1)/2 on the secp256k1 field.
func subOneOverTwo(c *big.Int) *big.Int {
	// This is modified by DivMod.
	curveOrder := new(big.Int).Set(curve.P)

	// (c - 1) mod p == (c + p - 1) mod p
	result := new(big.Int).Add(c, new(big.Int).Sub(curve.P, big.NewInt(1)))
	result.DivMod(result, big.NewInt(2), curveOrder)
	return result
}

// EncodeFieldElementToCurve uses the Shallue–van de Woestijne encoding from the
// paper "Indifferentiable Hashing to Barreto-Naehrig Curves" to map the given
// field element to a point on secp256k1. Note that this implementation is not
// constant time.
func EncodeFieldElementToCurve(t *big.Int) *Point {
	// Calculate the following:
	//    w = sqrt(-3) * t / (1 + b + t²)
	//   x1 = (-1 + sqrt(-3))/2 - t*w
	//   x2 = -(x1 + 1)
	//   x3 = 1 + 1/w^2

	tt := new(big.Int).Mul(t, t)
	tt.Mod(tt, curve.P)

	// Note that b = 7 for secp256k1.
	wd2 := new(big.Int).Add(big.NewInt(7+1), tt)
	wd2.ModInverse(wd2, curve.P)

	w := new(big.Int).Mul(sqrtMinusThree, t)
	w.Mul(w, wd2)
	w.Mod(w, curve.P)

	x1 := new(big.Int).Sub(sqrtMinusThreeSubOneOverTwo, new(big.Int).Mul(t, w))
	x1.Mod(x1, curve.P)

	x2 := new(big.Int).Add(big.NewInt(1), x1)
	x2.Sub(curve.P, x2)
	x2.Mod(x2, curve.P)

	wwInv := new(big.Int).Mul(w, w)
	wwInv.ModInverse(wwInv, curve.P)

	x3 := new(big.Int).Add(big.NewInt(1), wwInv)
	x3.Mod(x3, curve.P)

	// Compute y² = x³ + 7 for each x coordinate.

	alpha := new(big.Int).Mul(x1, x1)
	alpha.Mul(alpha, x1)
	alpha.Add(alpha, curve.Params().B)
	alpha.Mod(alpha, curve.P)
	y1 := ModSqrtFast(alpha)
	alphaQuadraticResidue := IsQuadraticResidue(alpha)

	beta := new(big.Int).Mul(x2, x2)
	beta.Mul(beta, x2)
	beta.Add(beta, curve.Params().B)
	beta.Mod(beta, curve.P)
	y2 := ModSqrtFast(beta)
	betaQuadraticResidue := IsQuadraticResidue(beta)

	gamma := new(big.Int).Mul(x3, x3)
	gamma.Mul(gamma, x3)
	gamma.Add(gamma, curve.Params().B)
	gamma.Mod(gamma, curve.P)
	y3 := ModSqrtFast(gamma)

	var x, y *big.Int
	if !alphaQuadraticResidue && betaQuadraticResidue {
		x = x2
		y = y2
	} else if !alphaQuadraticResidue && !betaQuadraticResidue {
		x = x3
		y = y3
	} else {
		x = x1
		y = y1
	}

	if isOdd(t) {
		y.Sub(curve.P, y) // negate y
	}

	xBytes := x.Bytes()
	yBytes := y.Bytes()
	return &Point{
		new(big.Int).SetBytes(xBytes[:]),
		new(big.Int).SetBytes(yBytes[:]),
	}
}

// createSingleGenerator computes a group element from hashing key32.
func createSingleGenerator(key32 []byte) *Point {
	var h []byte
	h = append(h, prefix1...)
	h = append(h, key32...)
	b32 := sha256.Sum256(h)

	var h2 []byte
	h2 = append(h2, prefix2...)
	h2 = append(h2, key32...)
	b322 := sha256.Sum256(h2)

	G1 := EncodeFieldElementToCurve(new(big.Int).SetBytes(b32[:]))
	G2 := EncodeFieldElementToCurve(new(big.Int).SetBytes(b322[:]))

	accumx, accumy := curve.Add(G1.X, G1.Y, G2.X, G2.Y)

	if !curve.IsOnCurve(accumx, accumy) {
		panic("should be on curve")
	}

	return &Point{accumx, accumy}
}

// GeneratorsCreate creates and returns a list of nothing-up-my-sleeve
// generator points.
func GeneratorsCreate(n int) []*Point {
	var seed []byte
	seed = append(seed, curve.Gx.Bytes()...)
	seed = append(seed, curve.Gy.Bytes()...)

	var points []*Point
	var t []byte

	v, k := newRFC6979(seed)

	for i := 0; i < n; i++ {
		t, v, k = generate(v, k)
		points = append(points, createSingleGenerator(t))
		v, k = update(v, k)
	}

	return points
}
