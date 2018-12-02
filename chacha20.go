package bulletproofs

import (
	"encoding/binary"
	"math/big"
)

var sigma = [4]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}

// This mirrors the behaviour of secp256k1_scalar_chacha20 in libsecp256k1.
func HashToScalars(seed [32]byte, idx uint32) (*big.Int, *big.Int) {
	overflowCount := uint32(0)

	// Repeatedly call chacha20 until we have two ints that are valid field
	// elements.
	for {
		v00 := sigma[0]
		v01 := sigma[1]
		v02 := sigma[2]
		v03 := sigma[3]
		v04 := binary.LittleEndian.Uint32(seed[0:])
		v05 := binary.LittleEndian.Uint32(seed[4:])
		v06 := binary.LittleEndian.Uint32(seed[8:])
		v07 := binary.LittleEndian.Uint32(seed[12:])
		v08 := binary.LittleEndian.Uint32(seed[16:])
		v09 := binary.LittleEndian.Uint32(seed[20:])
		v10 := binary.LittleEndian.Uint32(seed[24:])
		v11 := binary.LittleEndian.Uint32(seed[28:])
		v12 := idx
		v13 := idx >> 32
		v14 := uint32(0)
		v15 := overflowCount

		for i := 0; i < 20; i += 2 {
			v00 += v04
			v12 ^= v00
			v12 = (v12 << 16) | (v12 >> 16)
			v08 += v12
			v04 ^= v08
			v04 = (v04 << 12) | (v04 >> 20)
			v00 += v04
			v12 ^= v00
			v12 = (v12 << 8) | (v12 >> 24)
			v08 += v12
			v04 ^= v08
			v04 = (v04 << 7) | (v04 >> 25)
			v01 += v05
			v13 ^= v01
			v13 = (v13 << 16) | (v13 >> 16)
			v09 += v13
			v05 ^= v09
			v05 = (v05 << 12) | (v05 >> 20)
			v01 += v05
			v13 ^= v01
			v13 = (v13 << 8) | (v13 >> 24)
			v09 += v13
			v05 ^= v09
			v05 = (v05 << 7) | (v05 >> 25)
			v02 += v06
			v14 ^= v02
			v14 = (v14 << 16) | (v14 >> 16)
			v10 += v14
			v06 ^= v10
			v06 = (v06 << 12) | (v06 >> 20)
			v02 += v06
			v14 ^= v02
			v14 = (v14 << 8) | (v14 >> 24)
			v10 += v14
			v06 ^= v10
			v06 = (v06 << 7) | (v06 >> 25)
			v03 += v07
			v15 ^= v03
			v15 = (v15 << 16) | (v15 >> 16)
			v11 += v15
			v07 ^= v11
			v07 = (v07 << 12) | (v07 >> 20)
			v03 += v07
			v15 ^= v03
			v15 = (v15 << 8) | (v15 >> 24)
			v11 += v15
			v07 ^= v11
			v07 = (v07 << 7) | (v07 >> 25)
			v00 += v05
			v15 ^= v00
			v15 = (v15 << 16) | (v15 >> 16)
			v10 += v15
			v05 ^= v10
			v05 = (v05 << 12) | (v05 >> 20)
			v00 += v05
			v15 ^= v00
			v15 = (v15 << 8) | (v15 >> 24)
			v10 += v15
			v05 ^= v10
			v05 = (v05 << 7) | (v05 >> 25)
			v01 += v06
			v12 ^= v01
			v12 = (v12 << 16) | (v12 >> 16)
			v11 += v12
			v06 ^= v11
			v06 = (v06 << 12) | (v06 >> 20)
			v01 += v06
			v12 ^= v01
			v12 = (v12 << 8) | (v12 >> 24)
			v11 += v12
			v06 ^= v11
			v06 = (v06 << 7) | (v06 >> 25)
			v02 += v07
			v13 ^= v02
			v13 = (v13 << 16) | (v13 >> 16)
			v08 += v13
			v07 ^= v08
			v07 = (v07 << 12) | (v07 >> 20)
			v02 += v07
			v13 ^= v02
			v13 = (v13 << 8) | (v13 >> 24)
			v08 += v13
			v07 ^= v08
			v07 = (v07 << 7) | (v07 >> 25)
			v03 += v04
			v14 ^= v03
			v14 = (v14 << 16) | (v14 >> 16)
			v09 += v14
			v04 ^= v09
			v04 = (v04 << 12) | (v04 >> 20)
			v03 += v04
			v14 ^= v03
			v14 = (v14 << 8) | (v14 >> 24)
			v09 += v14
			v04 ^= v09
			v04 = (v04 << 7) | (v04 >> 25)
		}

		v00 += sigma[0]
		v01 += sigma[1]
		v02 += sigma[2]
		v03 += sigma[3]
		v04 += binary.LittleEndian.Uint32(seed[0:])
		v05 += binary.LittleEndian.Uint32(seed[4:])
		v06 += binary.LittleEndian.Uint32(seed[8:])
		v07 += binary.LittleEndian.Uint32(seed[12:])
		v08 += binary.LittleEndian.Uint32(seed[16:])
		v09 += binary.LittleEndian.Uint32(seed[20:])
		v10 += binary.LittleEndian.Uint32(seed[24:])
		v11 += binary.LittleEndian.Uint32(seed[28:])
		v12 += idx
		v13 += idx >> 32
		v14 += 0
		v15 += overflowCount

		resulta := [32]byte{}
		resultb := [32]byte{}

		binary.LittleEndian.PutUint32(resulta[0:], v00)
		binary.LittleEndian.PutUint32(resulta[4:], v01)
		binary.LittleEndian.PutUint32(resulta[8:], v02)
		binary.LittleEndian.PutUint32(resulta[12:], v03)
		binary.LittleEndian.PutUint32(resulta[16:], v04)
		binary.LittleEndian.PutUint32(resulta[20:], v05)
		binary.LittleEndian.PutUint32(resulta[24:], v06)
		binary.LittleEndian.PutUint32(resulta[28:], v07)

		binary.LittleEndian.PutUint32(resultb[0:], v08)
		binary.LittleEndian.PutUint32(resultb[4:], v09)
		binary.LittleEndian.PutUint32(resultb[8:], v10)
		binary.LittleEndian.PutUint32(resultb[12:], v11)
		binary.LittleEndian.PutUint32(resultb[16:], v12)
		binary.LittleEndian.PutUint32(resultb[20:], v13)
		binary.LittleEndian.PutUint32(resultb[24:], v14)
		binary.LittleEndian.PutUint32(resultb[28:], v15)

		r1 := new(big.Int).SetBytes(resulta[:])
		r2 := new(big.Int).SetBytes(resultb[:])

		// If these are not valid field elements then re-hash and try again.
		// This is to avoid biases.
		if r1.Cmp(curve.P) == 1 || r2.Cmp(curve.P) == 1 {
			overflowCount++
		} else {
			return r1, r2
		}
	}
}
