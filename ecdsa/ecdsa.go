package ecdsa

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdint.h>

// Define the struct to match the Rust ExtendedSignatureC struct
typedef struct {
    uint8_t r[32];
    uint8_t s[32];
} SignatureC;

typedef struct {
    const void* e;
} HashC;


// Function pointer type for sign_ecdsa
typedef int32_t (*sign_ecdsa_type)(const void*, const void*, SignatureC*);

// Function pointer type for hash_pedersen
typedef int32_t (*hash_pedersen_type)(const void*, const void*, HashC*);

// Wrapper function to call sign_ecdsa
int32_t sign_ecdsa(void* f, const void* private_key, const void* message, SignatureC* output) {
    return ((sign_ecdsa_type) f)(private_key, message, output);
}

// Wrapper function to call hash_pedersen
int32_t hash_pedersen(void* f, const void* e0, const void* e1, HashC* output) {
    return ((hash_pedersen_type) f)(e0, e1, output);
}
*/
import "C"
import (
	"fmt"
	"math/big"
	"unsafe"
)

var signSTARKPtr unsafe.Pointer
var signEd25519Ptr unsafe.Pointer
var hashPedersenPtr unsafe.Pointer

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
	hashPedersenPtr = C.dlsym(handle, C.CString("hash_pedersen"))
	if hashPedersenPtr == nil {
		panic("function hash_pedersen not found in the library")
	}
}

func SignSTARK(msgHash, privKey *big.Int) (r, s *big.Int, err error) {
	if signSTARKPtr == nil {
		return nil, nil, fmt.Errorf("library not loaded")
	}
	var signature C.SignatureC
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
	rBytes := C.GoBytes(unsafe.Pointer(&signature.r[0]), 32)
	sBytes := C.GoBytes(unsafe.Pointer(&signature.s[0]), 32)
	r = new(big.Int).SetBytes(rBytes)
	s = new(big.Int).SetBytes(sBytes)
	//fmt.Println("S", s.String())
	return
}

func HashPedersen(e0, e1 *big.Int) (e *big.Int, err error) {
	if hashPedersenPtr == nil {
		return nil, fmt.Errorf("library not loaded")
	}
	var hash C.HashC
	var e0Bytes, e1Bytes [32]byte
	e0.FillBytes(e0Bytes[:])
	e1.FillBytes(e1Bytes[:])
	//fmt.Println(privKeyBytes)
	//fmt.Println(fmt.Sprintf("%p, %p, %p, %p", signEcdsaPtr, unsafe.Pointer(&privKeyBytes[0]), unsafe.Pointer(&msgHashBytes[0]), unsafe.Pointer(&signature)))
	//res := trempoline.CallCFunc(uintptr(signEcdsaPtr), uintptr(unsafe.Pointer(&privKeyBytes[0])), uintptr(unsafe.Pointer(&msgHashBytes[0])), uintptr(unsafe.Pointer(&signature)))
	res := C.hash_pedersen(hashPedersenPtr, unsafe.Pointer(&e0Bytes[0]), unsafe.Pointer(&e1Bytes[0]), &hash)
	if res == -1 {
		return nil, fmt.Errorf("invalid arguments")
	} else if res == -2 {
		return nil, fmt.Errorf("invalid private key")
	}
	e = new(big.Int).SetBytes((*[32]byte)(hash.e)[:])
	return
}

/*
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
*/

func SignEd25519(msgHash, privKey *big.Int) (r, s *big.Int, err error) {
	if signEd25519Ptr == nil {
		return nil, nil, fmt.Errorf("library not loaded")
	}
	var signature C.SignatureC
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

/*

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

*/
