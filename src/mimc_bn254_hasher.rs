use serde::{Deserialize, Serialize};
use std::fmt::Debug;

use ark_bn254::Fr;
use ark_ff::fields::PrimeField;
use ark_ff::BigInteger;


use crate::mimc::mimc_hash_2;
// Bring your Merkle trait/types into scope
use crate::{MerkleHasher, StaticMerkleArray};

/* ------------------------------- Data type -------------------------------- */

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionRule {
    pub parent: (bool, u64),
    pub left_child: (bool, u64),
    pub right_child: (bool, u64),
}

/* ---------------------- Field-native hashing helpers ---------------------- */

const LEAF_DOMAIN: u64 = 0xA5; // arbitrary, distinct from node
const NODE_DOMAIN: u64 = 0x5A;

#[inline]
fn b2f(b: bool) -> Fr {
    if b {
        Fr::from(1u64)
    } else {
        Fr::from(0u64)
    }
}

#[inline]
fn u2f(x: u64) -> Fr {
    Fr::from(x)
}

#[inline]
fn fr_to_bytes32(x: Fr) -> [u8; 32] {
    // ark-ff 0.2.x: Fr::into_repr() -> BigInteger256
    let mut v = x.into_bigint().to_bytes_le();
    if v.len() < 32 {
        v.resize(32, 0);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v[..32]);
    out
}

#[inline]
fn bytes32_to_fr(b: &[u8; 32]) -> Fr {
    Fr::from_le_bytes_mod_order(b)
}

/// Hash a sequence of field elements with a MiMC-based MD-style compressor.
/// Domain is a field element (e.g., LEAF_DOMAIN or NODE_DOMAIN).
#[inline]
fn hash_frs(domain: Fr, parts: &[Fr]) -> Fr {
    let mut h = domain;
    for m in parts {
        h = mimc_hash_2(h, *m);
    }
    h
}

/// Encode a `ProductionRule` directly into field elements (no bytes).
#[inline]
fn rule_to_frs(r: &ProductionRule) -> [Fr; 6] {
    [
        b2f(r.parent.0),
        u2f(r.parent.1),
        b2f(r.left_child.0),
        u2f(r.left_child.1),
        b2f(r.right_child.0),
        u2f(r.right_child.1),
    ]
}

/* ----------------------------- The Hasher --------------------------------- */

#[derive(Clone, Copy, Debug, Default)]
pub struct MiMCBn254RuleHasher;

impl MerkleHasher for MiMCBn254RuleHasher {
    type Digest = [u8; 32];

    /// Leaf: interpret `T` as `ProductionRule` and hash its fields as `Fr`s.
    ///
    /// Note: This hasher is intended for `T = ProductionRule`. If used with a
    /// different `T`, it falls back to a generic (field-chunked) path.
    fn leaf<T: Serialize>(item: &T) -> Self::Digest {
        // Fast path for ProductionRule (no allocation, no (de)serialization):
        // SAFETY: The function is monomorphized per `T`. In typical usage
        // we instantiate `StaticMerkleArray<ProductionRule, _>`, so `T` == ProductionRule.
        // We avoid `unsafe` by trying a cheap bincode roundtrip to detect the type.
        if let Ok(buf) = bincode::serialize(item) {
            if let Ok(rule) = bincode::deserialize::<ProductionRule>(&buf) {
                let parts = rule_to_frs(&rule);
                let fr = hash_frs(Fr::from(LEAF_DOMAIN), &parts);
                fr_to_bytes32(fr)
            } else {
                // Generic fallback: interpret the serialized bytes as a sequence of Fr elements
                // (chunked LE, padded). Still hashes over field elements (not bytes).
                let mut parts = Vec::<Fr>::with_capacity((buf.len() + 31) / 32);
                for chunk in buf.chunks(32) {
                    let mut tmp = [0u8; 32];
                    tmp[..chunk.len()].copy_from_slice(chunk);
                    parts.push(Fr::from_le_bytes_mod_order(&tmp));
                }
                let fr = hash_frs(Fr::from(LEAF_DOMAIN), &parts);
                fr_to_bytes32(fr)
            }
        } else {
            // Extremely unlikely; keep deterministic behavior.
            let fr = hash_frs(Fr::from(LEAF_DOMAIN), &[]);
            fr_to_bytes32(fr)
        }
    }

    /// Node: convert child digests back to `Fr` and absorb with a NODE domain.
    fn node(left: &Self::Digest, right: &Self::Digest) -> Self::Digest {
        let l = bytes32_to_fr(left);
        let r = bytes32_to_fr(right);
        let fr = hash_frs(Fr::from(NODE_DOMAIN), &[l, r]);
        fr_to_bytes32(fr)
    }
}

/* ------------------------------- Type alias -------------------------------- */

pub type RuleMerkle = StaticMerkleArray<ProductionRule, MiMCBn254RuleHasher>;

/* ---------------------------------- Tests ---------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{verify_value_with_proof, StaticMerkleArray};

    #[test]
    fn rule_merkle_field_native_smoke() {
        let rules = vec![
            ProductionRule {
                parent: (true, 1),
                left_child: (false, 2),
                right_child: (true, 3),
            },
            ProductionRule {
                parent: (false, 10),
                left_child: (true, 11),
                right_child: (false, 12),
            },
            ProductionRule {
                parent: (true, 42),
                left_child: (true, 5),
                right_child: (false, 99),
            },
            ProductionRule {
                parent: (false, 7),
                left_child: (false, 8),
                right_child: (true, 9),
            },
        ];

        let sm: RuleMerkle = StaticMerkleArray::new(rules.clone());
        let sm2: RuleMerkle = StaticMerkleArray::new(rules.clone());
        assert_eq!(sm.root(), sm2.root());

        let p0 = sm.prove_index(0).unwrap();
        assert!(p0.verify());
        assert!(verify_value_with_proof(&rules[0], &p0));

        let p3 = sm.prove_index(3).unwrap();
        assert!(p3.verify());
        assert!(verify_value_with_proof(&rules[3], &p3));
    }

    #[test]
    fn persistence_roundtrip_mimc_rule() {
        use crate::verify_value_with_proof;

        // Some sample rules
        let rules = vec![
            ProductionRule {
                parent: (true, 1),
                left_child: (false, 2),
                right_child: (true, 3),
            },
            ProductionRule {
                parent: (false, 10),
                left_child: (true, 11),
                right_child: (false, 12),
            },
            ProductionRule {
                parent: (true, 42),
                left_child: (true, 5),
                right_child: (false, 99),
            },
            ProductionRule {
                parent: (false, 7),
                left_child: (false, 8),
                right_child: (true, 9),
            },
            ProductionRule {
                parent: (true, 123456789),
                left_child: (false, 111),
                right_child: (true, 222),
            },
        ];

        // Build and record root before saving
        let sm_before: RuleMerkle = StaticMerkleArray::new(rules.clone());
        let root_before = sm_before.root();

        // Save to a temp path
        let path = std::env::temp_dir().join(format!(
            "sma_mimc_rule_{}_{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        sm_before
            .save_to_file(&path)
            .expect("save_to_file should succeed");

        // Load back
        let sm_after: RuleMerkle =
            RuleMerkle::load_from_file(&path).expect("load_from_file should succeed");

        // Root should match
        assert_eq!(
            sm_after.root(),
            root_before,
            "roots must match after roundtrip"
        );

        // Proofs from the loaded structure should verify against the original values
        for &i in &[0usize, rules.len() - 1] {
            let proof = sm_after.prove_index(i).expect("prove_index");
            assert!(proof.verify(), "path recomposition must verify");
            assert!(
                verify_value_with_proof(&rules[i], &proof),
                "leaf binding must match the original value at index {i}"
            );
        }

        // best-effort cleanup
        let _ = std::fs::remove_file(&path);
    }
}
