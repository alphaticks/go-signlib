//go:build !cgo

package ecdsa

import (
	"fmt"
	"math/big"
)

func Loaded() bool {
	return false
}

func Load(path string) {
	panic("ecdsa: CGO required to load native library")
}

func SignSTARK(msgHash, privKey *big.Int) (r, s *big.Int, err error) {
	return nil, nil, fmt.Errorf("ecdsa: CGO required")
}

func HashPedersen(e0, e1 *big.Int) (e *big.Int, err error) {
	return nil, fmt.Errorf("ecdsa: CGO required")
}

func SignEd25519(msgHash, privKey *big.Int) (r, s *big.Int, err error) {
	return nil, nil, fmt.Errorf("ecdsa: CGO required")
}
