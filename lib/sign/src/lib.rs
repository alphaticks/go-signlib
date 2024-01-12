extern crate libc;
extern crate starknet;
extern crate ed25519_dalek;

use std::ffi::c_void;

use starknet::core::{crypto::ecdsa_sign, crypto::pedersen_hash, types::FieldElement};
use ed25519_dalek::{SigningKey, Signature, Signer};
use std::convert::TryInto;

#[repr(C)]
pub struct SignatureC {
    r: [u8; 32], // or appropriate C type
    s: [u8; 32], // or appropriate C type
}

#[repr(C)]
pub struct HashC {
    e: [u8; 32], // or appropriate C type
}

#[no_mangle]
pub extern "C" fn hash_pedersen(
    e0: *const c_void, // Pointer to private_key bytes
    e1: *const c_void,     // Pointer to message bytes
    output: *mut HashC, // Pointer to output buffer
) -> i32 {
    if e0.is_null() || e1.is_null() {
        return -1; // Indicate error due to null pointers
    }

    let fe0 = match FieldElement::from_bytes_be(unsafe { &*(e0 as *const [u8; 32]) }) {
        Ok(fe) => fe,
        Err(_) => return -1,
    };
    let fe1 = match FieldElement::from_bytes_be(unsafe { &*(e1 as *const [u8; 32]) }) {
        Ok(fe) => fe,
        Err(_) => return -1,
    };

    let fe = pedersen_hash(&fe0, &fe1);
    let fe_bytes = fe.to_bytes_be();

    // Populate the output structure
    unsafe {
        (*output).e.clone_from_slice(&fe_bytes);
    }
    0 // Success
}

#[no_mangle]
pub extern "C" fn sign_stark(
    private_key: *const c_void, // Pointer to private_key bytes
    message: *const c_void,     // Pointer to message bytes
    output: *mut SignatureC, // Pointer to output buffer
) -> i32 {
    if private_key.is_null() || message.is_null() || output.is_null() {
        return -1; // Indicate error due to null pointers
    }

    let private_key_fe = match FieldElement::from_bytes_be(unsafe { &*(private_key as *const [u8; 32]) }) {
        Ok(fe) => fe,
        Err(_) => return -1,
    };
    let message_fe = match FieldElement::from_bytes_be(unsafe { &*(message as *const [u8; 32]) }) {
        Ok(fe) => fe,
        Err(_) => return -1,
    };

   // Print private_key in hex
    //let private_key_bytes = unsafe { &*(private_key as *const [u8; 32]) };
    //let private_key_hex: Vec<String> = private_key_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    //println!("Private Key: {}", private_key_hex.join(""));

    // Print message in hex
    //let message_bytes = unsafe { &*(message as *const [u8; 32]) };
    //let message_hex: Vec<String> = message_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    //println!("Message: {}", message_hex.join(""));

    match ecdsa_sign(&private_key_fe, &message_fe) {
        Ok(signature) => {
            // Convert signature to C compatible type and write to output
            // Assuming ExtendedSignature has a way to be converted to SignatureC
            let r_bytes = signature.r.to_bytes_be();
            let s_bytes = signature.s.to_bytes_be();
            //let r_hex: Vec<String> = r_bytes.iter().map(|b| format!("{:02x}", b)).collect();
            //println!("R: {}", r_hex.join(""));

            //let s_hex: Vec<String> = s_bytes.iter().map(|b| format!("{:02x}", b)).collect();
            //println!("S: {}", s_hex.join(""));
            // Populate the output structure
            unsafe {
                (*output).r.clone_from_slice(&r_bytes);
                (*output).s.clone_from_slice(&s_bytes);
            }
            0 // Success
        },
        Err(_) => -2, // Indicate error due to sign failure
    }
}

#[no_mangle]
pub extern "C" fn sign_ed25519(
    private_key: *const c_void, // Pointer to private_key bytes
    message: *const c_void,     // Pointer to message bytes
    output: *mut SignatureC, // Pointer to output buffer
) -> i32 {
    if private_key.is_null() || message.is_null() || output.is_null() {
        return -1; // Indicate error due to null pointers
    }

    // Convert pointers to slices and then try converting to fixed-size arrays
    let private_key_slice = unsafe { std::slice::from_raw_parts(private_key as *const u8, 32) };

    let private_key_bytes: &[u8; 32] = match private_key_slice.try_into() {
        Ok(arr) => arr,
        Err(_) => return -1, // Indicate error in conversion
    };
    // Safely convert pointers to slices
    let message_bytes = unsafe { std::slice::from_raw_parts(message as *const u8, 32) };

    // Create keypair from private key bytes
    let signing_key: SigningKey = SigningKey::from_bytes(private_key_bytes);
    // Sign the message
    let signature: Signature = signing_key.sign(message_bytes);

    // Convert the signature to SignatureC format
    let signature_bytes: [u8; 64] = signature.to_bytes();
    let r_bytes = &signature_bytes[..32]; // First half of the signature
    let s_bytes = &signature_bytes[32..]; // Second half of the signature

    // Populate the output structure
    unsafe {
        (*output).r.clone_from_slice(&r_bytes);
        (*output).s.clone_from_slice(&s_bytes);
    }
    return 0
}
