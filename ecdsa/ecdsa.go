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
typedef void (*sign_ecdsa_type)(const void*, const void*, ExtendedSignatureC*);

// Wrapper function to call sign_ecdsa
void sign_ecdsa(void* f, const void* private_key, const void* message, ExtendedSignatureC* output) {
    ((sign_ecdsa_type) f)(private_key, message, output);
}
*/
import "C"
import (
	"fmt"
	"math/big"
	"os"
	"unsafe"
)

var signEcdsaPtr *C.void

func init() {
	handle := C.dlopen(C.CString(os.Getenv("STARKLIB_PATH")), C.RTLD_LAZY)
	if handle == nil {
		panic(fmt.Sprintf("failed to load the library: %s", os.Getenv("STARKLIB_PATH")))
	}
	signEcdsaPtr = C.dlsym(handle, C.CString("sign_ecdsa"))
	if signEcdsaPtr == nil {
		panic("function sign_ecdsa not found in the library")
	}
}

func Sign(msgHash, privKey *big.Int) (x, y *big.Int, err error) {
	var signature C.ExtendedSignatureC
	privKeyBytes := privKey.FillBytes(make([]byte, 32))
	msgHashBytes := msgHash.FillBytes(make([]byte, 32))
	C.sign_ecdsa(signEcdsaPtr, unsafe.Pointer(&privKeyBytes[0]), unsafe.Pointer(&msgHashBytes[0]), &signature)
	x = new(big.Int).SetBytes((*[32]byte)(signature.r)[:])
	y = new(big.Int).SetBytes((*[32]byte)(signature.s)[:])
	return
}
