package ecdsa

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdint.h>

// Define the struct to match the Rust ExtendedSignatureC struct
typedef struct {
    const void* r;
    const void* s;
    uint8_t v;
} ExtendedSignatureC;

// Function pointer type for sign_ecdsa
typedef int32_t (*sign_ecdsa_type)(const void*, const void*, ExtendedSignatureC*);

// Wrapper function to call sign_ecdsa
int32_t sign_ecdsa(void* f, const void* private_key, const void* message, ExtendedSignatureC* output) {
    return ((sign_ecdsa_type) f)(private_key, message, output);
}
*/
import "C"
import (
	"fmt"
	"math/big"
	"unsafe"
)

var signEcdsaPtr unsafe.Pointer

func Load(path string) {
	handle := C.dlopen(C.CString(path), C.RTLD_LAZY)
	if handle == nil {
		panic(fmt.Sprintf("failed to load the library: %s", path))
	}
	signEcdsaPtr = C.dlsym(handle, C.CString("sign_ecdsa"))
	if signEcdsaPtr == nil {
		panic("function sign_ecdsa not found in the library")
	}
}

func Sign(msgHash, privKey *big.Int) (r, s *big.Int, err error) {
	if signEcdsaPtr == nil {
		return nil, nil, fmt.Errorf("library not loaded")
	}
	var signature C.ExtendedSignatureC
	privKeyBytes := privKey.FillBytes(make([]byte, 32))
	msgHashBytes := msgHash.FillBytes(make([]byte, 32))
	res := C.sign_ecdsa(signEcdsaPtr, unsafe.Pointer(&privKeyBytes[0]), unsafe.Pointer(&msgHashBytes[0]), &signature)
	if res != 0 {
		return nil, nil, fmt.Errorf("failed to sign")
	}
	r = new(big.Int).SetBytes((*[32]byte)(signature.r)[:])
	s = new(big.Int).SetBytes((*[32]byte)(signature.s)[:])
	return
}
