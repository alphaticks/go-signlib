extern crate libc;
extern crate starknet;
use std::ffi::c_void;

use starknet::core::{crypto::ecdsa_sign, types::FieldElement};


#[repr(C)]
pub struct ExtendedSignatureC {
    r: *const c_void, // or appropriate C type
    s: *const c_void, // or appropriate C type
    v: u8,
}

#[no_mangle]
pub extern "C" fn sign_ecdsa(
    private_key: *const c_void, // Pointer to private_key bytes
    message: *const c_void,     // Pointer to message bytes
    output: *mut ExtendedSignatureC, // Pointer to output buffer
) -> i32 {
    if private_key.is_null() || message.is_null() || output.is_null() {
        return -1; // Indicate error due to null pointers
    }

    let private_key_fe = FieldElement::from_bytes_be(unsafe { &*(private_key as *const [u8; 32]) }).unwrap();
    let message_fe = FieldElement::from_bytes_be(unsafe { &*(message as *const [u8; 32]) }).unwrap();

    match ecdsa_sign(&private_key_fe, &message_fe) {
        Ok(signature) => {
            // Convert signature to C compatible type and write to output
            // Assuming ExtendedSignature has a way to be converted to ExtendedSignatureC
            let r_bytes = signature.r.to_bytes_be();
            let s_bytes = signature.s.to_bytes_be();

            let signature_c = ExtendedSignatureC {
                r: r_bytes.as_ptr() as *const c_void,
                s: s_bytes.as_ptr() as *const c_void,
                v: 0,
            };

            unsafe {
                *output = signature_c;
            }
            0 // Success
        },
        Err(_) => -2, // Indicate error due to sign failure
    }
}
