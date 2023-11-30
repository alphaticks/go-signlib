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
	"github.com/alphaticks/go-starklib/trempoline"
	"math/big"
	"unsafe"
)

var signSTARKPtr unsafe.Pointer
var signEd25519Ptr unsafe.Pointer

func Load(path string) {
	handle := C.dlopen(C.CString(path), C.RTLD_LAZY)
	if handle == nil {
		panic(fmt.Sprintf("failed to load the library: %s", path))
	}
	signSTARKPtr = C.dlsym(handle, C.CString("sign_stark"))
	if signSTARKPtr == nil {
		panic("function sign_stark not found in the library")
	}
	signEd25519Ptr = C.dlsym(handle, C.CString("sign_ed25519"))
	if signEd25519Ptr == nil {
		panic("function sign_ed25519 not found in the library")
	}
}

func SignSTARKCGO(msgHash, privKey *big.Int) (r, s *big.Int, err error) {
	if signSTARKPtr == nil {
		return nil, nil, fmt.Errorf("library not loaded")
	}
	var signature C.ExtendedSignatureC
	var privKeyBytes, msgHashBytes [32]byte
	privKey.FillBytes(privKeyBytes[:])
	msgHash.FillBytes(msgHashBytes[:])
	//fmt.Println(privKeyBytes)
	//fmt.Println(fmt.Sprintf("%p, %p, %p, %p", signEcdsaPtr, unsafe.Pointer(&privKeyBytes[0]), unsafe.Pointer(&msgHashBytes[0]), unsafe.Pointer(&signature)))
	//res := trempoline.CallCFunc(uintptr(signEcdsaPtr), uintptr(unsafe.Pointer(&privKeyBytes[0])), uintptr(unsafe.Pointer(&msgHashBytes[0])), uintptr(unsafe.Pointer(&signature)))
	res := C.sign_ecdsa(signSTARKPtr, unsafe.Pointer(&privKeyBytes[0]), unsafe.Pointer(&msgHashBytes[0]), &signature)
	if res == -1 {
		return nil, nil, fmt.Errorf("invalid arguments")
	} else if res == -2 {
		return nil, nil, fmt.Errorf("invalid private key")
	}
	//r = new(big.Int).SetBytes((*[32]byte)(signature.r)[:])
	//s = new(big.Int).SetBytes((*[32]byte)(signature.s)[:])
	return
}

func SignSTARKBypass(msgHash, privKey *big.Int) (r, s *big.Int, err error) {
	if signSTARKPtr == nil {
		return nil, nil, fmt.Errorf("library not loaded")
	}
	var signature C.ExtendedSignatureC
	var privKeyBytes, msgHashBytes [32]byte
	privKey.FillBytes(privKeyBytes[:])
	msgHash.FillBytes(msgHashBytes[:])
	//fmt.Println(privKeyBytes)
	//fmt.Println(fmt.Sprintf("%p, %p, %p, %p", signEcdsaPtr, unsafe.Pointer(&privKeyBytes[0]), unsafe.Pointer(&msgHashBytes[0]), unsafe.Pointer(&signature)))
	res := trempoline.Sign(uintptr(signSTARKPtr), uintptr(unsafe.Pointer(&privKeyBytes[0])), uintptr(unsafe.Pointer(&msgHashBytes[0])), uintptr(unsafe.Pointer(&signature)))
	//res := C.sign_ecdsa(signEcdsaPtr, unsafe.Pointer(&privKeyBytes[0]), unsafe.Pointer(&msgHashBytes[0]), &signature)
	if res == -1 {
		return nil, nil, fmt.Errorf("invalid arguments")
	} else if res == -2 {
		return nil, nil, fmt.Errorf("invalid private key")
	}
	//r = new(big.Int).SetBytes((*[32]byte)(signature.r)[:])
	//s = new(big.Int).SetBytes((*[32]byte)(signature.s)[:])
	return
}

func SignEd25519CGO(msgHash, privKey *big.Int) (r, s *big.Int, err error) {
	if signEd25519Ptr == nil {
		return nil, nil, fmt.Errorf("library not loaded")
	}
	var signature C.ExtendedSignatureC
	var privKeyBytes, msgHashBytes [32]byte
	privKey.FillBytes(privKeyBytes[:])
	msgHash.FillBytes(msgHashBytes[:])
	//fmt.Println(privKeyBytes)
	//fmt.Println(fmt.Sprintf("%p, %p, %p, %p", signEcdsaPtr, unsafe.Pointer(&privKeyBytes[0]), unsafe.Pointer(&msgHashBytes[0]), unsafe.Pointer(&signature)))
	//res := trempoline.CallCFunc(uintptr(signEcdsaPtr), uintptr(unsafe.Pointer(&privKeyBytes[0])), uintptr(unsafe.Pointer(&msgHashBytes[0])), uintptr(unsafe.Pointer(&signature)))
	res := C.sign_ecdsa(signEd25519Ptr, unsafe.Pointer(&privKeyBytes[0]), unsafe.Pointer(&msgHashBytes[0]), &signature)
	if res == -1 {
		return nil, nil, fmt.Errorf("invalid arguments")
	} else if res == -2 {
		return nil, nil, fmt.Errorf("invalid private key")
	}
	//r = new(big.Int).SetBytes((*[32]byte)(signature.r)[:])
	//s = new(big.Int).SetBytes((*[32]byte)(signature.s)[:])
	return
}

func SignEd25519Bypass(msgHash, privKey *big.Int) (r, s *big.Int, err error) {
	if signEd25519Ptr == nil {
		return nil, nil, fmt.Errorf("library not loaded")
	}
	var signature C.ExtendedSignatureC
	var privKeyBytes, msgHashBytes [32]byte
	privKey.FillBytes(privKeyBytes[:])
	msgHash.FillBytes(msgHashBytes[:])
	//fmt.Println(privKeyBytes)
	//fmt.Println(fmt.Sprintf("%p, %p, %p, %p", signEcdsaPtr, unsafe.Pointer(&privKeyBytes[0]), unsafe.Pointer(&msgHashBytes[0]), unsafe.Pointer(&signature)))
	res := trempoline.Sign(uintptr(signEd25519Ptr), uintptr(unsafe.Pointer(&privKeyBytes[0])), uintptr(unsafe.Pointer(&msgHashBytes[0])), uintptr(unsafe.Pointer(&signature)))
	//res := C.sign_ecdsa(signEcdsaPtr, unsafe.Pointer(&privKeyBytes[0]), unsafe.Pointer(&msgHashBytes[0]), &signature)
	if res == -1 {
		return nil, nil, fmt.Errorf("invalid arguments")
	} else if res == -2 {
		return nil, nil, fmt.Errorf("invalid private key")
	}
	//r = new(big.Int).SetBytes((*[32]byte)(signature.r)[:])
	//s = new(big.Int).SetBytes((*[32]byte)(signature.s)[:])
	return
}
