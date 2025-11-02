use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs;
use std::hash::Hash as StdHash;
use std::io::{Read};
use std::path::Path;
mod hash_constants;
mod mimc;
pub mod mimc_bn254_hasher;
mod utils;
/* --------------------------- MerkleHasher trait --------------------------- */

/// Pluggable hash behavior for the Merkle tree.
///
/// `Digest` is the node/leaf hash type (e.g., `[u8; 32]`, a newtype, etc).
/// You define how to hash a leaf (from a `T: Serialize`) and how to combine two child digests.
pub trait MerkleHasher {
    type Digest: Copy + Clone + Eq + StdHash + Serialize + DeserializeOwned + Debug;

    /// Hash a leaf value.
    fn leaf<T: Serialize>(item: &T) -> Self::Digest;

    /// Hash an internal node from its left/right child digests.
    fn node(left: &Self::Digest, right: &Self::Digest) -> Self::Digest;
}

/* -------------------------------------------------------------------------
Merkle Proof
------------------------------------------------------------------------- */

/// Indicates whether a sibling hash was to the left or right of the node
/// we are proving.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}

/// A Merkle proof of inclusion for a single array element.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(bound(
    serialize = "H::Digest: Serialize",
    deserialize = "H::Digest: DeserializeOwned"
))]
pub struct MerkleProof<H: MerkleHasher> {
    /// Original array index (0-based).
    pub index: usize,
    /// Sibling hashes + which side they came from (bottom to top).
    pub siblings: Vec<(H::Digest, Side)>, // bottom -> top
    /// The commitment root we expect.
    pub root: H::Digest,
    /// The leaf hash for the proven item.
    pub leaf: H::Digest,
}

impl<H: MerkleHasher> MerkleProof<H> {
    pub fn verify(&self) -> bool {
        let mut acc = self.leaf;
        for (sib, side) in &self.siblings {
            acc = match side {
                Side::Left => H::node(sib, &acc),
                Side::Right => H::node(&acc, sib),
            };
        }
        acc == self.root
    }

    pub fn save_to_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<(), MerkleError> {
        let bytes = bincode::serialize(self)?;
        std::fs::write(path, bytes)?;
        Ok(())
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, MerkleError> {
        let mut file = fs::File::open(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let me: Self = bincode::deserialize(&bytes)?;
        Ok(me)
    } 

    pub fn get_merkle_root(&self) -> H::Digest {
        self.root
    }

    pub fn get_leaf(&self) -> H::Digest {
        self.leaf
    }
}

/* -------------------------------------------------------------------------
Errors
------------------------------------------------------------------------- */

#[derive(thiserror::Error, Debug)]
pub enum MerkleError {
    #[error("index out of bounds")]
    IndexOob,
    #[error("item not found in array")]
    NotFound,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("bincode: {0}")]
    Codec(#[from] Box<bincode::ErrorKind>),
}

/* -------------------------------------------------------------------------
Static Merkle Array
------------------------------------------------------------------------- */

/// Static array Merkle commitment parameterized by the hasher `H`.
/// - Built once from an array of `T`.
/// - Supports membership proofs by index or by value.
/// - Serializable to disk via `bincode`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "H::Digest: Serialize, T: Serialize",
    deserialize = "H::Digest: DeserializeOwned, T: DeserializeOwned"
))]
pub struct StaticMerkleArray<T, H>
where
    T: Serialize + DeserializeOwned + Eq + Clone,
    H: MerkleHasher,
{
    items: Vec<T>,
    /// Bottom-up levels; levels[0] = leaves, levels.last() = [root]
    levels: Vec<Vec<H::Digest>>,
    /// Map leaf-digest -> positions (handles duplicates)
    index_map: HashMap<H::Digest, Vec<usize>>,
}

impl<T, H> StaticMerkleArray<T, H>
where
    T: Serialize + DeserializeOwned + Eq + Clone,
    // T: Serialize + for<'de> Deserialize<'de> + Eq + StdHash + Clone,
    H: MerkleHasher,
{
    /// Build the structure from an array of items.
    ///
    /// - Hash each item into a leaf.
    /// - Repeatedly combine pairs into parent nodes.
    /// - If a level has odd length, duplicate the last node (standard padding).
    pub fn new(items: Vec<T>) -> Self {
        assert!(!items.is_empty(), "array must be non-empty");

        let leaves: Vec<H::Digest> = items.iter().map(H::leaf).collect();

        // Build levels with duplicate padding
        let mut levels = Vec::new();
        let mut cur = leaves.clone();
        while cur.len() > 1 {
            if cur.len() % 2 == 1 {
                cur.push(*cur.last().unwrap());
            }
            let mut next = Vec::with_capacity((cur.len() + 1) / 2);
            for i in (0..cur.len()).step_by(2) {
                next.push(H::node(&cur[i], &cur[i + 1]));
            }
            levels.push(cur);
            cur = next;
        }
        levels.push(cur);

        let mut idx: HashMap<H::Digest, Vec<usize>> = HashMap::new();
        for (i, leaf) in leaves.iter().enumerate() {
            idx.entry(*leaf).or_default().push(i);
        }

        Self {
            items,
            levels,
            index_map: idx,
        }
    }

    /// Root commitment.
    pub fn root(&self) -> H::Digest {
        *self.levels.last().unwrap().first().unwrap()
    }

    /// Array length.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Is the array empty?
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Build a proof of membership for a given index.
    pub fn prove_index(&self, index: usize) -> Result<MerkleProof<H>, MerkleError> {
        if index >= self.len() {
            return Err(MerkleError::IndexOob);
        }
        let leaf = self.levels[0][index];
        let mut siblings = Vec::new();
        let mut i = index;

        // For each level up to root
        for level in 0..self.levels.len() - 1 {
            let level_nodes = &self.levels[level];
            let is_right = i % 2 == 1;
            let sib_idx = if is_right { i - 1 } else { i + 1 }.min(level_nodes.len() - 1);
            let sib = level_nodes[sib_idx];

            // Record sibling + side
            let side = if is_right { Side::Left } else { Side::Right };
            siblings.push((sib, side));
            i /= 2;
        }

        Ok(MerkleProof {
            index,
            siblings,
            root: self.root(),
            leaf,
        })
    }

    /// Return all positions of an item (works with duplicates).
    pub fn positions_of(&self, item: &T) -> Vec<usize> {
        let leaf = H::leaf(item);
        self.index_map.get(&leaf).cloned().unwrap_or_default()
    }

    /// Build a proof for a given item (by value).
    /// If it occurs multiple times, use `occurrence` to disambiguate.
    pub fn prove_item(
        &self,
        item: &T,
        occurrence: Option<usize>,
    ) -> Result<MerkleProof<H>, MerkleError> {
        let poss = self.positions_of(item);
        if poss.is_empty() {
            return Err(MerkleError::NotFound);
        }
        let idx = occurrence.unwrap_or(0);
        if idx >= poss.len() {
            return Err(MerkleError::NotFound);
        }
        self.prove_index(poss[idx])
    }

    /// Save the full structure to a file (binary encoding).
    pub fn save_to_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<(), MerkleError> {
        let bytes = bincode::serialize(self)?;
        std::fs::write(path, bytes)?;
        Ok(())
    }

    /// Load a structure from a file previously saved with `save_to_file`.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, MerkleError> {
        let mut file = fs::File::open(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let me: Self = bincode::deserialize(&bytes)?;
        Ok(me)
    }
}

/* -------------------------------------------------------------------------
Convenience
------------------------------------------------------------------------- */

/// Verify that a value belongs to the commitment, using its proof.
pub fn verify_value_with_proof<T, H>(value: &T, proof: &MerkleProof<H>) -> bool
where
    T: Serialize + DeserializeOwned,
    H: MerkleHasher,
{
    H::leaf(value) == proof.leaf && proof.verify()
}

/* ------------------------------- Tests ---------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use sha2::{Digest, Sha256};

    /// A 32-byte digest newtype so we can `Debug` as hex and use as map keys.
    #[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct Hash32([u8; 32]);

    impl std::fmt::Debug for Hash32 {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            for b in &self.0 {
                write!(f, "{:02x}", b)?;
            }
            Ok(())
        }
    }

    fn sha256(bytes: &[u8]) -> Hash32 {
        let mut h = Sha256::new();
        h.update(bytes);
        let out = h.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        Hash32(arr)
    }

    /// Domain separation tags for leaves and nodes.
    const LEAF_TAG: u8 = 0x00;
    const NODE_TAG: u8 = 0x01;

    /// Default SHA-256 hasher with the same encoding as before.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct Sha256Hasher;

    impl MerkleHasher for Sha256Hasher {
        type Digest = Hash32;

        fn leaf<T: Serialize>(item: &T) -> Self::Digest {
            let enc = bincode::serialize(item).expect("bincode serialize");
            let mut buf = Vec::with_capacity(1 + enc.len());
            buf.push(LEAF_TAG);
            buf.extend_from_slice(&enc);
            sha256(&buf)
        }

        fn node(left: &Self::Digest, right: &Self::Digest) -> Self::Digest {
            let mut buf = [0u8; 1 + 32 + 32];
            buf[0] = NODE_TAG;
            buf[1..33].copy_from_slice(&left.0);
            buf[33..].copy_from_slice(&right.0);
            sha256(&buf)
        }
    }

    type ShaSMA<T> = StaticMerkleArray<T, Sha256Hasher>;

    #[test]
    fn build_and_root() {
        let arr: Vec<u64> = (0..10).collect();
        let sm = ShaSMA::new(arr.clone());
        assert_eq!(sm.len(), 10);
        let root = sm.root();
        // Root should be stable for same data
        let sm2 = ShaSMA::new(arr);
        assert_eq!(root, sm2.root());
    }

    #[test]
    fn prove_and_verify_by_index() {
        let arr: Vec<u64> = (0..16).collect();
        let sm = ShaSMA::new(arr.clone());

        for i in 0..arr.len() {
            let proof = sm.prove_index(i).unwrap();
            assert!(proof.verify());
            assert!(verify_value_with_proof(&arr[i], &proof));
        }
    }

    #[test]
    fn prove_and_verify_by_value_with_duplicates() {
        // Array with duplicates
        let arr = vec![7u32, 1, 7, 2, 7, 3, 4, 7];
        let sm = ShaSMA::new(arr.clone());

        // Find all positions of 7
        let pos = sm.positions_of(&7);
        assert_eq!(pos, vec![0, 2, 4, 7]);

        // Prove first and third occurrence
        let p0 = sm.prove_item(&7, None).unwrap(); // first
        assert!(verify_value_with_proof(&7, &p0));
        assert_eq!(p0.index, 0);

        let p2 = sm.prove_item(&7, Some(2)).unwrap(); // third
        assert!(verify_value_with_proof(&7, &p2));
        assert_eq!(p2.index, 4);
    }

    #[test]
    fn persistence_roundtrip() {
        let arr: Vec<u64> = (0..25).collect();
        let sm = ShaSMA::new(arr.clone());
        let root_before = sm.root();

        let path = std::env::temp_dir().join("sma.bin");
        sm.save_to_file(&path).unwrap();
        let loaded: ShaSMA<u64> = ShaSMA::load_from_file(&path).unwrap();

        assert_eq!(loaded.root(), root_before);

        // Proof from loaded still verifies
        let proof = loaded.prove_index(13).unwrap();
        assert!(verify_value_with_proof(&arr[13], &proof));
    }

    #[test]
    fn proof_persistence_roundtrip() {
        let arr: Vec<u64> = (0..25).collect();
        let sm = ShaSMA::new(arr.clone());
        let root_before = sm.root();

        let path = std::env::temp_dir().join("sma.bin");
        

        // Proof from loaded still verifies
        let proof = sm.prove_index(13).unwrap();

        proof.save_to_file(&path).unwrap();
        let loaded_proof = MerkleProof::<Sha256Hasher>::load_from_file(&path).unwrap();
        assert_eq!(loaded_proof.get_merkle_root(), root_before);
        assert!(verify_value_with_proof(&arr[13], &proof));
        assert!(verify_value_with_proof(&arr[13], &loaded_proof));
    }

    #[test]
    fn random_array_smoke() {
        let mut rng = rand::thread_rng();
        let n = 31; // non-power-of-two to test padding
        let mut arr = vec![0u64; n];
        for x in &mut arr {
            *x = rng.gen::<u64>();
        }
        let sm = ShaSMA::new(arr.clone());
        // Try a handful of random indices
        for _ in 0..8 {
            let i = rng.gen_range(0..n);
            let p = sm.prove_index(i).unwrap();
            assert!(verify_value_with_proof(&arr[i], &p));
        }
    }
}
