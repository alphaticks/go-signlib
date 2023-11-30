// +build amd64,!appengine

#include "textflag.h"

// func callCFunc(fn uintptr, r *byte, s *byte, sig *ExtendedSignatureC) int32
TEXT ·Sign(SB), 0, $0-40
    MOVQ fn+0(FP), AX       // Move the function address into AX
    MOVQ r+8(FP), DI         // Move the first argument into DI (RDI)
    MOVQ s+16(FP), SI        // Move the second argument into SI (RSI)
    MOVQ sig+24(FP), DX      // Move the third argument into DX (RDX)

    MOVQ SP, BX         // Save SP
    SUBQ $16384, SP
    ANDQ $~15, SP      // Align the stack to 16-bytes

    CALL AX            // Call the function
    MOVQ BX, SP        // Restore SP

    MOVQ AX, ret+32(FP)     // Move return value
    RET

