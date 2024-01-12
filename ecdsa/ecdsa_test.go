package ecdsa

import (
	"math/big"
	"testing"
)

func TestEcdsa(t *testing.T) {
	priv, _ := new(big.Int).SetString("2694640734420098289168932321453844877445981823409726840565151125758414758195", 10)
	k, _ := new(big.Int).SetString("1860628535426984640718681250822843799056280994042392077290961110599908043918", 10)
	_, _, err := SignSTARK(k, priv)
	if err != nil {
		t.Fatal(err)
	}
}
