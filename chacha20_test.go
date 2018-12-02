package bulletproofs

import (
	"math/big"
	"testing"
)

func TestChaCha20(t *testing.T) {
	ones := [32]byte{}
	for i := 0; i < 32; i++ {
		ones[i] = 0x01
	}
	r1, r2 := HashToScalars(ones, 0)

	expectedR1, _ := new(big.Int).SetString("023f37203a2476c42566a61cc55c3ca875dbb4cc41c0deb789f8e7bf88183638", 16)
	expectedR2, _ := new(big.Int).SetString("1ecc3686b60ee3b84b6c7d321d70d5c06e9dac63a4d0a79d731b17c0d04d030d", 16)

	if r1.Cmp(expectedR1) != 0 {
		t.Errorf("TestChaCha20 wrong result\n"+
			"got:  %v\nwant: %v", r1, expectedR1)
	}

	if r2.Cmp(expectedR2) != 0 {
		t.Errorf("TestChaCha20 wrong result\n"+
			"got:  %v\nwant: %v", r2, expectedR2)
	}
}
