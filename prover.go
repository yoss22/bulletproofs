package bulletproofs

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"math/big"
)

// commitVectors returns a vector Pedersen commitment to aL and aR using
// randomness alpha. A = αh + a_L G + a_R H.
func commitVectors(alpha *big.Int, h *Point, aL []*big.Int, G []*Point,
	aR []*big.Int, H []*Point) *Point {
	return SumPoints(
		ScalarMulPoint(h, alpha),
		ScalarMulPoints(aL, G),
		ScalarMulPoints(aR, H))
}

// left returns the even indexed entries in s.
func left(s []*big.Int) []*big.Int {
	var r []*big.Int
	for i := range s {
		if i&1 == 0 { // even
			r = append(r, s[i])
		}
	}
	return r
}

// right returns the odd indexed entries in s.
func right(s []*big.Int) []*big.Int {
	var r []*big.Int
	for i := range s {
		if i&1 == 1 { // odd
			r = append(r, s[i])
		}
	}
	return r
}

// leftP returns the even indexed entries in s.
func leftP(s []*Point) []*Point {
	var r []*Point
	for i := range s {
		if i&1 == 0 { // even
			r = append(r, s[i])
		}
	}
	return r
}

// rightP returns the odd indexed entries in s.
func rightP(s []*Point) []*Point {
	var r []*Point
	for i := range s {
		if i&1 == 1 { // odd
			r = append(r, s[i])
		}
	}
	return r
}

// commit computes the Pedersen commitment γH + vG.
func commit(gamma *big.Int, h *Point, v *big.Int, g *Point) *Point {
	return SumPoints(ScalarMulPoint(h, gamma), ScalarMulPoint(g, v))
}

// powers returns ascending powers of the challenge.
func powers(challenge *big.Int, m int) []*big.Int {
	eExpI := make([]*big.Int, m)
	for i := 0; i < m; i++ {
		eExpI[i] = new(big.Int).Exp(challenge, big.NewInt(int64(i)), curve.N)
	}
	return eExpI
}

// bitVector returns a slice containing the coefficients of ascending powers of
// two that constitute a.
func bitVector(a *big.Int, n int) []*big.Int {
	var bits []*big.Int
	for i := 0; i < n; i++ {
		bits = append(bits, big.NewInt(int64(a.Bit(i))))
	}
	return bits
}

// computeAR returns a vector a_R such that a_L ○ a_R = 0, the vector of zeros.
func computeAR(aL []*big.Int) []*big.Int {
	return SubVectors(aL, Ones(len(aL)))
}

// computeL returns evaluates l(x) = a_L - z*1^n + s_L*x. This is equation (58).
func computeL(n int, x, z *big.Int, aL, sL []*big.Int) []*big.Int {
	return AddVectors(SubVectors(aL, VectorOf(n, z)), ScalarMul(sL, x))
}

// computeR returns evaluates r(x) = y^n ○ (a_R + z*1^n + s_R*x) + z^2*2^n. This
// is equation (59).
func computeR(n int, x, z, zz *big.Int, aR, sR, Y, twoN []*big.Int) []*big.Int {
	return AddVectors(
		Hadamard(Y, AddVectors3(aR, VectorOf(n, z), ScalarMul(sR, x))),
		ScalarMul(twoN, zz))
}

// computeSLAndSR returns two random vectors of length n derived from the given
// nonce.
func computeSLAndSR(n int, nonce [32]byte) ([]*big.Int, []*big.Int) {
	sL := make([]*big.Int, n)
	sR := make([]*big.Int, n)
	for j := 0; j < n; j++ {
		sL[j], sR[j] = HashToScalars(nonce, uint32(j+2))
	}
	return sL, sR
}

// proverCommitToT returns two commitments T1 and T2 which commit to the
// coefficients t_1 and t_2 of the polynomial given by l(X)·r(X).
func proverCommitToT(n int, z, zz, tau1, tau2 *big.Int, aL, aR, sL, sR, Y,
	powersOfTwo []*big.Int, h, g *Point) (*Point, *Point, *big.Int, *big.Int,
	*big.Int) {
	// l(X), r(X) are linear vector polynomials in ℤ^n_p[X]. Their inner product
	// l(X)·r(X) is a quadratic polynomial, t(X) ∈ ℤ_p[X].

	// As t(X) is a polynomial of degree 2 we can write it as
	// t(x) = t_0 + t_1*x + t_2*x^2 where t_i are scalars. Now we can do some
	// fun tricks to determine these coefficients. Clearly if we evaluate t at
	// zero we'll get
	//   t(0) = l(0)·r(0) = t_0 + t_1*0 + t_2*0^2 = t_0.

	t0 := Dot(
		computeL(n, big.NewInt(0), z, aL, sL),
		computeR(n, big.NewInt(0), z, zz, aR, sR, Y, powersOfTwo))

	// Similarly we can evaluate t at 1, which gives us
	//   t(1) = l(1)·r(1) = t_0 + t_1*1 + t_2*1^2 = t_0 + t_1 + t_2
	// This will be helpful in a moment.
	tOne := Dot(
		computeL(n, big.NewInt(1), z, aL, sL),
		computeR(n, big.NewInt(1), z, zz, aR, sR, Y, powersOfTwo))

	minusOne := new(big.Int).Sub(curve.N, big.NewInt(1))

	// The final evaluation of t at -1 give us
	//   t(-1) = l(-1)·r(-1) = t_0 + t_1*-1 + t_2*(-1)^2 = t_0 - t_1 + t_2
	tMinusOne := Dot(
		computeL(n, minusOne, z, aL, sL),
		computeR(n, minusOne, z, zz, aR, sR, Y, powersOfTwo))

	// Now we do some rearranging to get t_1, t_2:
	//   (t(1)-t(-1))
	//       = (t_0 + t_1 + t_2 - t_0 + t_1 - t_2)
	//       = (2*t_1)
	//   t_2 = t(-1) - t_0 + t_1
	negTminusOne := new(big.Int).Sub(curve.N, tMinusOne)
	t1 := new(big.Int).Add(tOne, negTminusOne)
	t1.Mul(t1, Inv(big.NewInt(2))) // divide by two
	t1.Mod(t1, curve.N)

	t2 := Sum(tMinusOne, Neg(t0), t1)

	// Create the Pedersen commitments to the coefficients t_1, t_2.
	T1 := commit(tau1, h, t1, g) // T1 = t_1 * G + tau_1 * H
	T2 := commit(tau2, h, t2, g) // T2 = t_2 * G + tau_2 * H

	return T1, T2, t0, t1, t2
}

// updateCommit hashes the given data in order to generate a non-interactive
// challenge.
func updateCommit(commit [32]byte, lpt, rpt *Point) ([32]byte, *big.Int) {
	// If Jacobi(a, P) = −1 then a is a quadratic nonresidue modulo P, i.e. a is
	// not a square.
	lQuadraticNonResidue := big.Jacobi(lpt.Y, curve.P) == -1
	rQuadraticNonResidue := big.Jacobi(rpt.Y, curve.P) == -1

	lrparity := byte(0)
	if lQuadraticNonResidue {
		lrparity = 2
	}
	if rQuadraticNonResidue {
		lrparity++
	}

	lx := GetB32(lpt.X)
	rx := GetB32(rpt.X)

	var h []byte
	h = append(h, commit[:]...)
	h = append(h, lrparity)
	h = append(h, lx[:]...)
	h = append(h, rx[:]...)
	sum := sha256.Sum256(h)

	return sum, new(big.Int).SetBytes(sum[:])
}

// verifyInnerProductProof recursively combines the generators G, H with the
// invariant that the dot product is maintained.
func verifyInnerProductProof(i, n int, challenges []*big.Int, Ls []*Point,
	Rs []*Point, a []*big.Int, b []*big.Int, P, u *Point, G, H []*Point) bool {
	nPrime := n / 2

	// Bring the generators down to the correct dimension as the provided a, b
	// vectors so we can check that they form a valid inner product.
	if n == len(a) {
		PRhs1 := SumPoints(ScalarMulPoints(a, G), ScalarMulPoints(b, H),
			ScalarMulPoint(u, Dot(a, b)))

		return P.Equals(PRhs1)
	}

	x := challenges[i]
	xInv := Inv(x)

	Gprime := HadamardP(
		ScalarMultArray(xInv, leftP(G)),
		ScalarMultArray(x, rightP(G)))
	Hprime2 := HadamardP(
		ScalarMultArray(x, leftP(H)),
		ScalarMultArray(xInv, rightP(H)))

	Pprime := SumPoints(
		ScalarMulPoint(Ls[i], Square(x)),
		P,
		ScalarMulPoint(Rs[i], Square(xInv)))

	return verifyInnerProductProof(i+1, nPrime, challenges, Ls, Rs, a, b,
		Pprime, u, Gprime, Hprime2)
}

// createInnerProductProof implements the logarithmic inner product argument
// from the bulletproofs paper.
func createInnerProductProof(i, n int, commit [32]byte, G, H []*Point, g, u,
	P *Point, a, b []*big.Int, Ls, Rs []*Point) (
	[]*Point, []*Point, []*big.Int, []*big.Int) {
	nPrime := n / 2

	// At each stage of the recursion the inner product relation should still
	// hold.
	PRhs1 := SumPoints(ScalarMulPoints(a, G), ScalarMulPoints(b, H),
		ScalarMulPoint(u, Dot(a, b)))
	if !P.Equals(PRhs1) {
		panic("proof isn't correct")
	}

	// Stop early. The proof takes the same amount of space, but the
	// verification is one iteration less expensive.
	if n == 2 {
		return Ls, Rs, a, b
	}

	cL := Dot(left(a), right(b))
	cR := Dot(right(a), left(b))

	Li := SumPoints(
		ScalarMulPoints(left(a), rightP(G)),
		ScalarMulPoints(right(b), leftP(H)),
		ScalarMulPoint(u, cL))

	Ri := SumPoints(
		ScalarMulPoints(right(a), leftP(G)),
		ScalarMulPoints(left(b), rightP(H)),
		ScalarMulPoint(u, cR))

	Ls = append(Ls, Li)
	Rs = append(Rs, Ri)

	commit, x := updateCommit(commit, Li, Ri)
	xInv := Inv(x)

	Gprime := HadamardP(
		ScalarMultArray(xInv, leftP(G)),
		ScalarMultArray(x, rightP(G)))
	Hprime2 := HadamardP(
		ScalarMultArray(x, leftP(H)),
		ScalarMultArray(xInv, rightP(H)))

	Pprime := SumPoints(
		ScalarMulPoint(Li, Square(x)),
		P,
		ScalarMulPoint(Ri, Square(xInv)))

	aprime := AddVectors(
		ScalarMul(left(a), x),
		ScalarMul(right(a), xInv))

	bprime := AddVectors(
		ScalarMul(left(b), xInv),
		ScalarMul(right(b), x))

	return createInnerProductProof(i+1, nPrime, commit, Gprime, Hprime2, g, u,
		Pprime, aprime, bprime, Ls, Rs)
}

// BulletProof is a zero knowledge argument of knowledge that a committed value
// lies withing a specific range. See rangeProofCreate for a full explanation of
// these values.
type BulletProof struct {
	negTaux *big.Int   // The blinding factors in tHat.
	negMu   *big.Int   // The blinding factors in A and S.
	tHat    *big.Int   // The result of the inner product l(x) · r(x).
	T1      *Point     // A commitment to the t_1 coefficient of t(X).
	T2      *Point     // A commitment to the t_2 coefficient of t(X).
	A       *Point     // A commitment to aL and aR.
	S       *Point     // A commitment to the blinding vectors sL and sR.
	a, b    []*big.Int // Constants at the tail of the inner product proof.
	Ls, Rs  []*Point   // The log(n) points from the inner product proof.
}

// Read deserializes a single proof.
func (p *BulletProof) Read(r io.Reader) error {
	buf := [32]byte{}
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return err
	}
	p.negTaux = new(big.Int).SetBytes(buf[:])

	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return err
	}
	p.negMu = new(big.Int).SetBytes(buf[:])

	// Usually points would be serialized as 32 bytes for the x-coordinate, then
	// one byte for the y sign. However, we can store the signs for multiple
	// points as a bit vector which saves a few bytes.
	buf2 := [1 + 32*4]byte{}
	if _, err := io.ReadFull(r, buf2[:]); err != nil {
		return err
	}

	points, err := DeserializePoints(buf2[:], 4)
	if err != nil {
		return err
	}
	p.A = points[0]
	p.S = points[1]
	p.T1 = points[2]
	p.T2 = points[3]

	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return err
	}
	p.tHat = new(big.Int).SetBytes(buf[:])

	// a's then b's
	numScalars := 2
	for i := 0; i < numScalars; i++ {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return err
		}
		p.a = append(p.a, new(big.Int).SetBytes(buf[:]))
	}
	for i := 0; i < numScalars; i++ {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return err
		}
		p.b = append(p.b, new(big.Int).SetBytes(buf[:]))
	}

	// Read Ls and Rs.
	LRs := uint(6 - 1) // log2(64) - 1

	bitvecSize := (2*LRs + 7) / 8
	buf3 := make([]byte, bitvecSize+2*LRs*32)
	if _, err := io.ReadFull(r, buf3); err != nil {
		return err
	}
	points, err = DeserializePoints(buf3, 2*LRs)
	if err != nil {
		return err
	}

	p.Ls = leftP(points)
	p.Rs = rightP(points)

	return nil
}

// Bytes serializes the range proof.
func (p *BulletProof) Bytes() []byte {
	buff := new(bytes.Buffer)

	fixed := GetB32(p.negTaux)
	if _, err := buff.Write(fixed[:]); err != nil {
		logrus.Fatal(err)
	}

	fixed = GetB32(p.negMu)
	if _, err := buff.Write(fixed[:]); err != nil {
		logrus.Fatal(err)
	}

	if _, err := buff.Write(SerializePoints(
		[]*Point{p.A, p.S, p.T1, p.T2})); err != nil {
		logrus.Fatal(err)
	}

	fixed = GetB32(p.tHat)
	if _, err := buff.Write(fixed[:]); err != nil {
		logrus.Fatal(err)
	}

	for _, a := range p.a {
		fixed = GetB32(a)
		if _, err := buff.Write(fixed[:]); err != nil {
			logrus.Fatal(err)
		}
	}

	for _, b := range p.b {
		fixed = GetB32(b)
		if _, err := buff.Write(fixed[:]); err != nil {
			logrus.Fatal(err)
		}
	}

	// Write as L1, R1, L2, R2, ...
	var LRs []*Point
	for i := 0; i < len(p.Ls); i++ {
		LRs = append(LRs, p.Ls[i])
		LRs = append(LRs, p.Rs[i])
	}
	if _, err := buff.Write(SerializePoints(LRs)); err != nil {
		logrus.Fatal(err)
	}

	return buff.Bytes()
}

// encodeValueAndMessage encodes the committed value v and an optional 16 byte
// message into the range proof. These values can be recovered from the proof
// by someone that knows the original nonce.
func encodeValueAndMessage(alpha, v *big.Int, message [16]byte) {
	// The value v is at most 64 bits so if we want to encode a message we have
	// a bunch more space we can use. Encode the message into v then subtract
	// that from alpha.
	vBytes := GetB32(v)
	for i := 0; i < 16; i++ {
		vBytes[i+8] = message[i]
	}

	// alpha - v
	alpha.Add(alpha, new(big.Int).Sub(curve.N, new(big.Int).SetBytes(vBytes[:])))
	alpha.Mod(alpha, curve.N)
}

// hash concatenates elements and returns the SHA256 hash of them.
func hash(elements ...[32]byte) [32]byte {
	var hash []byte
	for i := range elements {
		hash = append(hash, elements[i][:]...)
	}
	return sha256.Sum256(hash)
}

// computeHPrime returns the generators H multiplied by powers of y^-1.
func computeHPrime(H []*Point, y *big.Int) []*Point {
	// y^{-n} == (y^{-1})^n
	yExpNegN := powers(Inv(y), len(H))

	// H' is a set of generators derived from H. (64)
	Hprime := make([]*Point, len(H))
	for i := range H {
		Hprime[i] = ScalarMulPoint(H[i], yExpNegN[i])
	}

	return Hprime
}

// rangeProofCreate creates a zero knowledge argument of knowledge that
// convinces a verifier that the committed value lies within a specific
// range.
//
// The range proof is built by taking the binary representation of the value
// v and creating a commitment to each bit of v. The prover proves that an
// inner product relation holds which is only true if v is within the range and
// if all the commitments to the bits commit to 0 or 1.
func rangeProofCreate(n int, V *Point, v, gamma *big.Int, g, h *Point,
	G, H []*Point, nonce [32]byte, message [16]byte, powersOfTwo []*big.Int) (
	BulletProof, error) {
	// commit contains the hashed data that is used as a random oracle to make
	// this proof non-interactive.
	commit := [32]byte{0}
	commit, _ = updateCommit(commit, V, g)

	// This additional hash is here to match the behaviour of libsecp256k1 with
	// a non-null empty extra_data field.
	commit = hash(commit)

	// Maximum range proof that we'll calculate is 2^64.
	if n > 64 {
		return BulletProof{}, fmt.Errorf("range too large")
	}

	aL := bitVector(v, n) // the bit vector of v
	aR := computeAR(aL)   // the "complement" vector of aL, aL - 1.

	// Ensure v is actually within the range.
	if Dot(aL, powersOfTwo).Cmp(v) != 0 {
		return BulletProof{}, fmt.Errorf("value is out of range")
	}

	// Compute random blinding factors for the commitments A and S.
	alpha, rho := HashToScalars(nonce, 0)

	// As alpha is an arbitrary blinding factor we can add another value to it
	// which can be recovered later (as long as we know what the original alpha
	// was). This adjusted alpha can be recovered from mu in the proof.
	encodeValueAndMessage(alpha, v, message)

	// commit to the bit vectors aL and aR with blinding factor alpha.
	A := commitVectors(alpha, h, aL, G, aR, H)

	// The vectors sL and sR serve to blind aL and aR later on.
	sL, sR := computeSLAndSR(n, nonce)
	S := commitVectors(rho, h, sL, G, sR, H)

	commit, y := updateCommit(commit, A, S)
	commit, z := updateCommit(commit, A, S)
	zz := Square(z)
	zzz := Mul(zz, z)
	powersOfY := powers(y, n)

	// We have three constraints on aL that we must prove to convince a verifier
	// that aL really is a bit-vector for v. The verifier sends a challenge, y,
	// that we cannot predict in advance then we show the following hold:
	//
	// 1. That aL is some linear combination of powers of 2 (though this doesn't
	//    prove that aL is a bit vector, the remaining two checks serve to
	//    ensure elements in aL are in {0,1}).
	//      Dot(aL, 2^n) = v
	//
	// 2. That aR is the complement vector of aL (by proving that elements of
	//    aR are zero when the corresponding element of aL is non-zero).
	//      Dot(aL, aR ○ y^n) = 0
	//
	// 3. That aL - aR = 1, which it should be if aL and aR were constructed
	//    honestly. We verify this by proving that (aL - 1^n - aR) is the zero
	//    vector.
	//      Dot(aL - 1^n - aR, y^n) = 0
	//
	// These three constraints are combined into a polynomial function of a
	// second challenge z:
	//
	//		z^2(Dot(aL, 2^n))
	//    + z(Dot(aL, aR ○ y^n))
	//    + Dot(aL - 1^n - aR, y^n)
	//    = z^2 v
	//
	// Then we re-arrange into a single inner product:
	//   Dot(aL - z * 1^n, y^n ○ (aR + z * 1^n) + z^2 * 2^n) = z^2 * v + delta(y,z)

	// Compute delta(y,z) = (z - z^2) * (1^n · y^n) - z^3 * (1^n · 2^n)
	delta := new(big.Int).Sub(
		Mul(new(big.Int).Sub(z, zz), Sum(powersOfY...)),
		Mul(zzz, Sum(powersOfTwo...)))
	delta.Mod(delta, curve.N)

	// Finally, we blind the terms in the inner product (with sL, sR) so we can
	// freely transfer them to a verifier without leaking aL.
	//    l(X) = (aL - z*1^n) + sL*X
	//    r(X) = y^n ○ (aR + z*1^n + sR*X) + z^2*2^n
	//    t(X) = Dot(l(X), r(X))
	//         = t_0 + t_1*X + t_2*X^2
	//
	// By expanding out Dot(l(X), r(X)) we get three scalar coefficients t_0,
	// t_1 and t_2 which, by construction, t_0 is the result of the original
	// inner product without the blinding terms sL, sR.
	//
	// In order to prove to the verifier that we have honestly constructed t(X)
	// we send Pedersen commitments to the coefficients t_1 and t_2, these are
	// T1 and T2.

	// Compute random blinding factors for the commitments T1 and T2.
	tau1, tau2 := HashToScalars(nonce, 1)

	T1, T2, _, _, _ := proverCommitToT(n, z, zz, tau1, tau2, aL, aR, sL, sR,
		powersOfY, powersOfTwo, h, g)

	// The verifier now sends a challenge x that we use to compute L = l(x) and
	// R = r(x).
	commit, x := updateCommit(commit, T1, T2)
	L := computeL(n, x, z, aL, sL)
	R := computeR(n, x, z, zz, aR, sR, powersOfY, powersOfTwo)
	tHat := Dot(L, R)

	// Blinding factors in t̂.
	taux := Sum(
		Mul(tau2, x, x), // factor for T2
		Mul(tau1, x),    // factor for T1
		Mul(zz, gamma))  // factor for V

	// The verifier checks the following equality holds under the commitments
	// provided by the prover:
	//   Dot(l(x), r(x)) = t_0 + t_1*x + t_2*x^2
	//                   = z^2 * v + delta(y,z) + t_1*x + t_2*x^2
	//
	// i.e. it verifies that:
	//   tHat * G + taux * H == z^2 * V + delta * G + x * T1 + x^2 * T2
	//
	// The verifier must also check that the commitments A and S are valid which
	// is true if:
	//   A + x*S - z*G + (z*y^n +z^2*2^n)*H' == (α + ρ)*H + L*G + R*H'

	// α, ρ blind A, S
	mu := Sum(alpha, Mul(rho, x))

	// Under the new generators, A is now a vector commitment to (a_L,
	// a_R ○ y^n) and similarly S is now a vector commitment to (s_L, s_R ○ y^n
	// ).
	Hprime := computeHPrime(H, y)

	// Sanity check that the commitments A and S are valid.
	P := SumPoints(
		A,
		ScalarMulPoint(S, x),
		ScalarMultAll(Neg(z), G...),
		ScalarMulPoints(
			AddVectors(ScalarMul(powersOfY, z), ScalarMul(powersOfTwo, zz)),
			Hprime))

	expected := SumPoints(
		ScalarMulPoint(h, mu),
		ScalarMulPoints(L, G),
		ScalarMulPoints(R, Hprime))

	if !P.Equals(expected) {
		panic("range proof sanity check failed")
	}

	// At this point we could just send L and R and have the prover verify it.
	// That would be fine, but we can do it in less space.

	commit = hash(commit, GetB32(Neg(taux)), GetB32(Neg(mu)))
	commit = hash(commit, GetB32(tHat))

	ux := new(big.Int).SetBytes(commit[:])

	u := h

	Pprime := SumPoints(
		ScalarMulPoints(L, G),
		ScalarMulPoints(R, Hprime),
		ScalarMulPoint(u, Mul(ux, tHat)))

	Ls, Rs, a, b := createInnerProductProof(0, len(L), commit, G, Hprime, g,
		ScalarMulPoint(u, ux), Pprime, L, R, nil, nil)

	return BulletProof{
		negTaux: Neg(taux),
		negMu:   Neg(mu),
		A:       A,
		S:       S,
		T1:      T1,
		T2:      T2,
		tHat:    tHat,
		a:       a,
		b:       b,
		Ls:      Ls,
		Rs:      Rs,
	}, nil
}

// ComputeChallenges computes non-interactive challenges in the same way that
// is used in rangeProofCreate.
func ComputeChallenges(V, g *Point, proof BulletProof) (*big.Int,
	*big.Int, *big.Int, *big.Int, []*big.Int) {
	commit := [32]byte{0}
	commit, _ = updateCommit(commit, V, g)
	commit = hash(commit)
	commit, y := updateCommit(commit, proof.A, proof.S)
	commit, z := updateCommit(commit, proof.A, proof.S)
	commit, x := updateCommit(commit, proof.T1, proof.T2)
	commit = hash(commit, GetB32(proof.negTaux), GetB32(proof.negMu))
	commit = hash(commit, GetB32(proof.tHat))

	ux := new(big.Int).SetBytes(commit[:])

	// Compute challenges x_i.
	xs := make([]*big.Int, len(proof.Ls))
	for i := range xs {
		commit, xs[i] = updateCommit(commit, proof.Ls[i], proof.Rs[i])
	}

	return y, z, x, ux, xs
}

// rangeProofVerify takes a range proof using the construction in
// rangeProofCreate and asserts that the committed value v lies in the given
// range.
func rangeProofVerify(n int, V *Point, proof BulletProof, g, h *Point, G,
	H []*Point) bool {
	y, z, x, ux, xs := ComputeChallenges(V, g, proof)

	yN := powers(y, n)
	twoN := powers(big.NewInt(2), n)
	zz := Square(z)
	zzz := Mul(z, zz)
	Hprime := computeHPrime(H, y)

	// Ensure that t(x) = L · R.
	delta := new(big.Int).Sub(
		Mul(new(big.Int).Sub(z, zz), Sum(yN...)),
		Mul(zzz, Sum(twoN...)))
	delta.Mod(delta, curve.N)

	rhs65 := SumPoints(
		ScalarMulPoint(V, Square(z)),
		ScalarMulPoint(g, delta),
		ScalarMulPoint(proof.T1, x),
		ScalarMulPoint(proof.T2, Square(x)))

	// Check that the prover constructed the inner product honestly.
	if !commit(Neg(proof.negTaux), h, proof.tHat, g).Equals(rhs65) {
		return false
	}

	// P above contains mu, so construct a P without it.
	P := SumPoints(
		proof.A,
		ScalarMulPoint(proof.S, x),
		ScalarMultAll(Neg(z), G...),
		ScalarMulPoints(AddVectors(ScalarMul(yN, z), ScalarMul(twoN, Square(z))), Hprime),
		ScalarMulPoint(h, proof.negMu))

	Pprime := SumPoints(P, ScalarMulPoint(h, Mul(ux, proof.tHat)))

	return verifyInnerProductProof(0, n, xs, proof.Ls, proof.Rs,
		proof.a, proof.b, Pprime, ScalarMulPoint(h, ux), G, Hprime)
}

// Prover is a range proof prover and verifier.
type Prover struct {
	// n is the maximum value that this prover will prove or verify as an
	// exponent of 2. For example, if n is 64 the generated proofs will be for
	// values in the range [0, 2^64-1].
	n                 int
	G, H              []*Point   // a set of nothing-up-my-sleeve generator points on secp256k1.
	ValueGenerator    *Point     // the generator point used for committing to a value.
	BlindingGenerator *Point     // the generator point used for blinding factors.
	powersOfTwo       []*big.Int // a vector of pre-computed powers of 2.
}

// NewProver returns a new instance of a range proof Prover that supports
// proving and verifying values up to 2^n-1.
func NewProver(n int) *Prover {
	maxGenerators := 256
	generators := GeneratorsCreate(maxGenerators)
	G := generators[0 : maxGenerators/2]
	H := generators[maxGenerators/2:]

	gx, _ := new(big.Int).SetString("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0", 16)
	gy, _ := new(big.Int).SetString("31d3c6863973926e049e637cb1b5f40a36dac28af1766968c30c2313f3a38904", 16)
	g := Point{X: gx, Y: gy}

	h := Point{X: curve.Gx, Y: curve.Gy}

	powersOfTwo := powers(big.NewInt(2), n)

	return &Prover{
		n:                 n,
		G:                 G,
		H:                 H,
		ValueGenerator:    &g,
		BlindingGenerator: &h,
		powersOfTwo:       powersOfTwo,
	}
}

// Verify takes a committed value V and checks whether the supplied range proof
// is valid to prove that V commits to a 64-bit positive integer.
func (v *Prover) Verify(V *Point, proof BulletProof) bool {
	return rangeProofVerify(v.n, V, proof, v.ValueGenerator,
		v.BlindingGenerator, v.G[:v.n], v.H[:v.n])
}

// CreateRangeProof creates a zero knowledge argument of knowledge that
// convinces a verifier that the committed value lies within a specific
// range.
func (v *Prover) CreateRangeProof(V *Point, value, gamma *big.Int,
	nonce [32]byte, message [16]byte) (BulletProof, error) {
	return rangeProofCreate(v.n, V, value, gamma, v.ValueGenerator,
		v.BlindingGenerator, v.G[:v.n], v.H[:v.n], nonce, message,
		v.powersOfTwo)
}
