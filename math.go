package bulletproofs

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"math/big"
)

// Point is a group element of the secp256k1 curve in affine coordinates.
type Point struct {
	X *big.Int
	Y *big.Int
}

// Equals returns true if the given point is the same.
func (p *Point) Equals(other *Point) bool {
	return p.X.Cmp(other.X) == 0 && p.Y.Cmp(other.Y) == 0
}

// String prints the coordinates of this point.
func (p *Point) String() string {
	return fmt.Sprintf("{x: %032x, y: %032x}", p.X.Bytes(), p.Y.Bytes())
}

// Read deserializes a compressed elliptic curve point from the reader.
func (p *Point) Read(r io.Reader) error {
	buf := make([]byte, 32+1)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	sign := buf[0]
	x := new(big.Int).SetBytes(buf[1:])

	if (sign & 0xfe) != 8 {
		return errors.New("point is not serialized correctly")
	}

	// Derive the possible y coordinates from the secp256k1 curve
	// y² = x³ + 7.
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Add(x3, curve.Params().B)

	// y = ±sqrt(x³ + 7).
	y := ModSqrtFast(x3)

	// Pick which y from the sign encoded in the first byte.
	if (sign & 1) != 0 {
		y = new(big.Int).Sub(curve.P, y)
	}

	p.X = x
	p.Y = y

	return nil
}

// serializedPedersenCommitment is the constant that is encoded to signal that
// the encoded value is a Pedersen commitment, rather than a standard compressed
// curve point.
const serializedPedersenCommitment = byte(9)

// Bytes compresses and serializes the point.
func (p *Point) Bytes() []byte {
	buff := new(bytes.Buffer)

	sign := serializedPedersenCommitment
	if IsQuadraticResidue(p.Y) {
		sign ^= 1
	}

	if err := buff.WriteByte(sign); err != nil {
		logrus.Fatal(err)
	}

	x := GetB32(p.X)
	if _, err := buff.Write(x[:]); err != nil {
		logrus.Fatal(err)
	}

	return buff.Bytes()
}

// isOdd returns true if the given integer is odd.
func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}

// ModSqrtOrig returns a value v such that v*v = x mod P.
func ModSqrtOrig(x *big.Int) *big.Int {
	return new(big.Int).ModSqrt(x, curve.Params().P)
}

// ModSqrtFast returns a value v such that v*v = x mod P. This is about twice as
// fast as ModSqrtOrig. See: https://bitcointalk.org/index.php?topic=162805.msg1712294#msg1712294
func ModSqrtFast(x *big.Int) *big.Int {
	return new(big.Int).Exp(x, curve.QPlus1Div4(), curve.Params().P)
}

// IsQuadraticResidue returns true if there exists some x such that
// x*x = y mod P.
func IsQuadraticResidue(y *big.Int) bool {
	return big.Jacobi(y, curve.P) >= 0
}

// SerializePoints returns a byte slice containing a bit vector that indicates
// whether the points
func SerializePoints(points []*Point) []byte {
	bitvec := make([]byte, (len(points)+7)/8)

	// Encode whether each y value is a quadratic residue, so when we decompress
	// the points we can determine the sign of the y coordinate.
	for i, point := range points {
		if !IsQuadraticResidue(point.Y) {
			bitvec[i/8] |= 1 << (uint(i) % 8)
		}
	}

	// Now write all the x coordinates as fixed 32-byte integers.
	buff := new(bytes.Buffer)
	for _, point := range points {
		x := GetB32(point.X)
		if _, err := buff.Write(x[:]); err != nil {
			logrus.Fatal(err)
		}
	}

	return append(bitvec, buff.Bytes()...)
}

// DeserializePoints parses num points that have been serialized using
// SerializePoints.
func DeserializePoints(buf []byte, num uint) ([]*Point, error) {
	bitvecSize := (num + 7) / 8
	isNonResidue := buf[0:bitvecSize]
	xcoords := buf[bitvecSize:]

	points := make([]*Point, num)
	for i := uint(0); i < num; i++ {
		x := new(big.Int).SetBytes(xcoords[i*32 : (i+1)*32])

		// Derive the possible y coordinates from the secp256k1 curve
		// y² = x³ + 7.
		x3 := new(big.Int).Mul(x, x)
		x3.Mul(x3, x)
		x3.Add(x3, curve.Params().B)

		// y = ±sqrt(x³ + 7).
		y := ModSqrtFast(x3)

		// Pick which y from the bit vector.
		if isNonResidue[i/8]&(1<<(i%8)) != 0 {
			y = new(big.Int).Sub(curve.P, y)
		}

		points[i] = new(Point)
		points[i].Y = y
		points[i].X = x
	}

	return points, nil
}

// ScalarMulPoint multiplies a point by a scalar.
func ScalarMulPoint(point *Point, scalar *big.Int) *Point {
	x, y := curve.ScalarMult(point.X, point.Y, scalar.Bytes())
	return &Point{x, y}
}

// ScalarMultAll multiplies all points by the given scalar and sums the results.
func ScalarMultAll(scalar *big.Int, points ...*Point) *Point {
	initial := ScalarMulPoint(points[0], scalar)
	sumx := new(big.Int).Set(initial.X)
	sumy := new(big.Int).Set(initial.Y)
	for i := 1; i < len(points); i++ {
		mult := ScalarMulPoint(points[i], scalar)
		sumx, sumy = curve.Add(sumx, sumy, mult.X, mult.Y)
	}
	return &Point{sumx, sumy}
}

// ScalarMulPoints multiplies each point with the corresponding scalar and sums
// the results. This function will panic if the number of scalars and points
// differ.
func ScalarMulPoints(scalars []*big.Int, points []*Point) *Point {
	if len(scalars) != len(points) {
		panic("len(scalars) != len(points)")
	}
	initial := ScalarMulPoint(points[0], scalars[0])
	sumx := new(big.Int).Set(initial.X)
	sumy := new(big.Int).Set(initial.Y)
	for i := 1; i < len(points); i++ {
		mult := ScalarMulPoint(points[i], scalars[i])
		sumx, sumy = curve.Add(sumx, sumy, mult.X, mult.Y)
	}
	return &Point{sumx, sumy}
}

// ScalarMul returns the vector that is the result of the scalar multiplication
// of vector and scalar.
func ScalarMul(vector []*big.Int, scalar *big.Int) []*big.Int {
	result := make([]*big.Int, len(vector))
	for i := range vector {
		result[i] = Mul(vector[i], scalar)
	}
	return result
}

// ScalarMultArray multiplies each point in the vector points by the scalar xi
// and returns them as a vector.
func ScalarMultArray(xi *big.Int, points []*Point) []*Point {
	result := make([]*Point, len(points))
	for i := range points {
		result[i] = ScalarMulPoint(points[i], xi)
	}
	return result
}

// Square computes and returns z*z.
func Square(z *big.Int) *big.Int {
	return Mul(z, z)
}

// AddVectors returns the vector z = a + b. This function will panic if the vectors are
// of different length.
func AddVectors(a []*big.Int, b []*big.Int) []*big.Int {
	if len(a) != len(b) {
		panic("vectors must be equal dimension")
	}
	z := make([]*big.Int, len(a))
	for i := range a {
		z[i] = Sum(a[i], b[i])
	}
	return z
}

// AddVectors3 returns the vector z = a + b + c.
func AddVectors3(a []*big.Int, b []*big.Int, c []*big.Int) []*big.Int {
	if len(a) != len(b) || len(a) != len(c) {
		panic("vectors must be equal dimension")
	}
	z := make([]*big.Int, len(a))
	for i := range a {
		z[i] = Sum(a[i], b[i], c[i])
	}
	return z
}

// Dot computes the inner product of two vectors of length n: a · b =
// a_1 * b_1 + a_2 * b_2 + ··· + a_n * b_n.
func Dot(a, b []*big.Int) *big.Int {
	if len(a) != len(b) {
		panic("vectors must have same length")
	}
	result := big.NewInt(0)
	for i := 0; i < len(a); i++ {
		result.Add(result, Mul(a[i], b[i]))
	}
	result.Mod(result, curve.N)
	return result
}

// SubScalars returns the scalar a - b.
func SubScalars(a, b *big.Int) *big.Int {
	aMinusB := new(big.Int).Sub(a, b)
	aMinusB.Mod(aMinusB, curve.N)
	return aMinusB
}

// SubVectors returns the vector a - b. This function will panic if the vectors are of
// different lengths.
func SubVectors(a, b []*big.Int) []*big.Int {
	if len(a) != len(b) {
		panic("vectors must have same length")
	}
	var result []*big.Int
	for i := 0; i < len(a); i++ {
		result = append(result, SubScalars(a[i], b[i]))
	}
	return result
}

// Ones returns a vector of length n where all elements are 1.
func Ones(n int) []*big.Int {
	ones := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		ones[i] = big.NewInt(1)
	}
	return ones
}

// Hadamard computes the vector given by element-wise multiplication of the two
// given vectors. a ○ b = (a_0*b_0 a_1*b_1 ... a_n*b_n). This function will
// panic if the vectors have different lengths.
func Hadamard(a, b []*big.Int) []*big.Int {
	if len(a) != len(b) {
		panic("vectors must be the same length")
	}
	result := make([]*big.Int, len(a))
	for i := 0; i < len(a); i++ {
		result[i] = Mul(a[i], b[i])
	}
	return result
}

// HadamardP computes the element-wise point addition of the two vectors. This
// function will panic if the vectors have different lengths.
func HadamardP(a []*Point, b []*Point) []*Point {
	if len(a) != len(b) {
		panic("vectors must be the same length")
	}
	result := make([]*Point, len(a))
	for i := range a {
		result[i] = new(Point)
		result[i].X, result[i].Y = curve.Add(a[i].X, a[i].Y, b[i].X, b[i].Y)
	}
	return result
}

// Sum adds the given numbers and returns the total sum.
func Sum(nums ...*big.Int) *big.Int {
	sum := new(big.Int).Set(nums[0])
	for i := 1; i < len(nums); i++ {
		sum.Add(sum, nums[i])
	}
	sum.Mod(sum, curve.N)
	return sum
}

// SumPoints adds the given curve points and returns the total sum.
func SumPoints(points ...*Point) *Point {
	sumx := new(big.Int).Set(points[0].X)
	sumy := new(big.Int).Set(points[0].Y)
	for i := 1; i < len(points); i++ {
		sumx, sumy = curve.Add(sumx, sumy, points[i].X, points[i].Y)
	}
	return &Point{
		X: sumx,
		Y: sumy,
	}
}

// Mul returns the product of the given integers.
func Mul(nums ...*big.Int) *big.Int {
	prod := new(big.Int).Set(nums[0])
	for i := 1; i < len(nums); i++ {
		prod.Mul(prod, nums[i])
	}
	prod.Mod(prod, curve.N)
	return prod
}

// VectorOf returns a length n vector of vs.
func VectorOf(n int, v *big.Int) []*big.Int {
	vec := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		vec[i] = new(big.Int).Set(v)
	}
	return vec
}

// Neg returns the additive inverse of z modulo the group order, i.e. -z such
// that z + (-z) = 0 mod N.
func Neg(z *big.Int) *big.Int {
	x := new(big.Int).Sub(curve.N, z)
	return x.Mod(x, curve.N)
}

// Inv returns the multiplicative inverse of z modulo the group order, i.e. z^-1
// such that z * z^-1 = 1 mod N.
func Inv(z *big.Int) *big.Int {
	return new(big.Int).ModInverse(z, curve.N)
}

// GetB32 returns a fixed size 32-byte slice containing the big-endian
// representation of num. This function will panic if the given number does not
// fit into 32 bytes.
func GetB32(num *big.Int) [32]byte {
	numBytes := num.Bytes()
	if len(numBytes) > 32 {
		panic("num doesn't fit in 32 bytes")
	}
	var b [32]byte
	offset := 32 - len(numBytes)
	for i := offset; i < 32; i++ {
		b[i] = numBytes[i-offset]
	}
	return b
}
