use ark_ff::PrimeField;
use hex::FromHex;
use num_bigint::BigUint;
use num_traits::Num;

#[allow(unused)] // temporary
/// hex string → BN254 field element  (handles any length ≤ 64 hex chars)
pub(crate) fn hex_to_fr(h: &str) -> ark_bn254::Fr {
    // 1. strip "0x"
    let s = h.trim_start_matches("0x");

    // 2. guarantee even length by padding, producing an owned String
    let padded: String = if s.len() % 2 == 1 {
        format!("0{s}") // allocates a new String
    } else {
        s.to_owned() // still produces a String
    };

    // 3. decode big‑endian hex → bytes
    let mut bytes: Vec<u8> = Vec::from_hex(&padded).unwrap();

    // 4. left‑pad to 32 bytes (BN254 modulus fits in 254 bits)
    if bytes.len() < 32 {
        let mut pad = vec![0u8; 32 - bytes.len()];
        pad.extend_from_slice(&bytes);
        bytes = pad;
    }

    // 5. convert big‑endian bytes → field element
    ark_bn254::Fr::from_be_bytes_mod_order(&bytes)
}

fn decimal_str_to_bytes_be(dec: &str) -> Vec<u8> {
    // 1) Parse the decimal string into a BigUint (base 10)
    let n = BigUint::from_str_radix(dec, 10).expect("invalid decimal string");

    // 2) Convert to big-endian bytes
    

    // (Optional) If you need a fixed length (e.g. pad to 32 bytes):
    // let desired_len = 32;
    // if bytes.len() < desired_len {
    //     let mut padded = vec![0u8; desired_len - bytes.len()];
    //     padded.extend_from_slice(&bytes);
    //     bytes = padded;
    // }

    n.to_bytes_be()
}

pub(crate) fn int_to_fr(s: &str) -> ark_bn254::Fr {
    // 2. guarantee even length by padding, producing an owned String
    let padded: String = if s.len() % 2 == 1 {
        format!("0{s}") // allocates a new String
    } else {
        s.to_owned() // still produces a String
    };

    // 3. decode big‑endian hex → bytes
    let mut bytes: Vec<u8> = decimal_str_to_bytes_be(&padded); //Vec::from_hex(&padded).unwrap();

    // 4. left‑pad to 32 bytes (BN254 modulus fits in 254 bits)
    if bytes.len() < 32 {
        let mut pad = vec![0u8; 32 - bytes.len()];
        pad.extend_from_slice(&bytes);
        bytes = pad;
    }

    // 5. convert big‑endian bytes → field element
    ark_bn254::Fr::from_be_bytes_mod_order(&bytes)
}
