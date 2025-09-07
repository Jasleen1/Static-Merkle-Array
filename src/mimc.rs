use ark_ff::Field;

use crate::hash_constants::{MIMC_ROUNDS, MIMC_ROUND_CONSTANTS_110};
use crate::utils::int_to_fr;

pub fn mimc_hash_2(a: ark_bn254::Fr, b: ark_bn254::Fr) -> ark_bn254::Fr {
    // Initialize state by summing inputs
    let mut x = a + b;

    // Apply MiMC round function: x = (x + c_i)^5
    for i in 0..MIMC_ROUNDS {
        let c = int_to_fr(MIMC_ROUND_CONSTANTS_110[i]);
        let exponent = 5u64;
        x = (x + c).pow([exponent]);
    }

    // Return the final state as the hash
    x
}
