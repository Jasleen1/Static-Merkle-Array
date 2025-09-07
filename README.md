# Static Merkle Array (SMA)

A lightweight, generic **static Merkle commitment over an array** with:

- **Pluggable hash** via the `MerkleHasher` trait
- **Generic element type `T`** (any `Serialize + DeserializeOwned + Eq + Clone`)
- **Membership proofs by index** *and* **by value** (supports duplicates)
- **Binary persistence** with `bincode` (`save_to_file` / `load_from_file`)
- Simple, explicit proof verification (`MerkleProof::verify`) and helper `verify_value_with_proof`

> This crate builds a bottom‑up Merkle tree with duplicate padding (if a level has odd length, the last node is duplicated). Leaves and internal nodes are hashed using the `MerkleHasher` provided by you.

---

## Table of contents

- [Quick start](#quick-start)
- [Data model](#data-model)
- [Hash plug‑in model (`MerkleHasher`)](#hash-plug-in-model-merklehasher)
- [Example A: Field‑native MiMC over BN254 (for `ProductionRule`)](#example-a-field-native-mimc-over-bn254-for-productionrule)
- [Example B: Custom type + SHA‑256 hasher](#example-b-custom-type--sha-256-hasher)
- [Persistence (save / load)](#persistence-save--load)
- [Proofs](#proofs)
- [Design notes & tips](#design-notes--tips)
- [Run tests](#run-tests)

---

## Quick start

```rust
use your_crate::{
    StaticMerkleArray,
    verify_value_with_proof,
};

// 1) Pick or implement a Merkle hasher
//    Here we’ll use the MiMC/BN254 hasher and ProductionRule type provided by the crate.
use your_crate::mimc_bn254_hasher::{ProductionRule, MiMCBn254RuleHasher};

type RuleMerkle = StaticMerkleArray<ProductionRule, MiMCBn254RuleHasher>;

fn main() {
    let rules = vec![
        ProductionRule { parent: (true, 1),  leftChild: (false, 2), rightChild: (true, 3) },
        ProductionRule { parent: (false, 10), leftChild: (true, 11), rightChild: (false, 12) },
        ProductionRule { parent: (true, 42), leftChild: (true, 5), rightChild: (false, 99) },
        ProductionRule { parent: (false, 7), leftChild: (false, 8), rightChild: (true, 9) },
    ];

    // 2) Build once
    let tree: RuleMerkle = StaticMerkleArray::new(rules.clone());

    // 3) Get root commitment
    let root = tree.root();
    println!("root: 0x{}", hex::encode(root));

    // 4) Prove/verify membership by index
    let i = 2usize;
    let proof = tree.prove_index(i).unwrap();
    assert!(proof.verify());
    assert!(verify_value_with_proof(&rules[i], &proof));

    // 5) Prove/verify by value (supports duplicates)
    let positions = tree.positions_of(&rules[0]);
    let by_val_proof = tree.prove_item(&rules[0], None).unwrap();
    assert!(verify_value_with_proof(&rules[0], &by_val_proof));

    // 6) Persist to disk and load later (see section below for details)
    tree.save_to_file("/tmp/sma_rules.bin").unwrap();
    let loaded: RuleMerkle = RuleMerkle::load_from_file("/tmp/sma_rules.bin").unwrap();
    assert_eq!(loaded.root(), root);
}
```

> Replace `your_crate` above with your actual crate name if you’re using this as a library; if you’re in the same workspace/binary, `use crate::…` is fine.

---

## Data model

```rust
pub struct StaticMerkleArray<T, H>
where
    T: Serialize + DeserializeOwned + Eq + Clone,
    H: MerkleHasher,
{
    items: Vec<T>,
    levels: Vec<Vec<H::Digest>>,  // levels[0] = leaves; levels.last() = [root]
    index_map: HashMap<H::Digest, Vec<usize>>, // leaf-digest -> all positions
}
```

- **Build** with `StaticMerkleArray::new(items)`. Complexity is `O(n)` hashing plus `O(n)` node combines.
- **Root** with `.root()`.
- **Proofs** with `.prove_index(i)` or `.prove_item(&value, occurrence)`. Duplicates are supported; `positions_of(&value)` returns all indices.

---

## Hash plug‑in model (`MerkleHasher`)

```rust
pub trait MerkleHasher {
    type Digest: Copy + Clone + Eq + std::hash::Hash + Serialize + DeserializeOwned + Debug;

    fn leaf<T: Serialize>(item: &T) -> Self::Digest;
    fn node(left: &Self::Digest, right: &Self::Digest) -> Self::Digest;
}
```

- `Digest` can be any fixed‑size byte array (e.g., `[u8; 32]`) or newtype that satisfies the bounds.
- `leaf` defines how to hash a **value** into a leaf digest.
- `node` defines how to combine **two child digests** into a parent.
- **Tip:** add **domain separation** (different prefixes/tags) so leaf and node spaces don’t collide.

---

## Example A: Field‑native MiMC over BN254 (for `ProductionRule`)

This crate includes a ready‑to‑use **field‑native** MiMC x⁷/91‑rounds over BN254 that treats all fields of `ProductionRule` as **field elements**, not bytes.

```rust
use your_crate::{StaticMerkleArray, verify_value_with_proof};
use your_crate::mimc_bn254_hasher::{ProductionRule, MiMCBn254RuleHasher};

type RuleMerkle = StaticMerkleArray<ProductionRule, MiMCBn254RuleHasher>;

fn example_mimc_rules() {
    let rules = vec![
        ProductionRule { parent: (true, 1),  leftChild: (false, 2), rightChild: (true, 3) },
        ProductionRule { parent: (false, 10), leftChild: (true, 11), rightChild: (false, 12) },
    ];
    let tree: RuleMerkle = StaticMerkleArray::new(rules.clone());
    let proof = tree.prove_index(1).unwrap();
    assert!(verify_value_with_proof(&rules[1], &proof));
}
```

### Why field‑native?
- Avoids serialization ambiguity and makes the hash algebraic‑friendly (good for ZK/SNARK contexts).
- Internally converts `bool → {0,1}` and `u64 → Fr` and absorbs via a MiMC permutation with clear domain separators for leaves vs. nodes.

---

## Example B: Custom type + SHA‑256 hasher

Here’s how to use **your own data type** with a **different hash**. We’ll implement a small SHA‑256 hasher with domain separation and use it for a `Person` type.

```rust
use serde::{Serialize, Deserialize};
use sha2::{Digest as _, Sha256};
use your_crate::{MerkleHasher, StaticMerkleArray, verify_value_with_proof};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Person { id: u64, name: String }

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct Hash32([u8; 32]);

impl std::fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in &self.0 { write!(f, "{:02x}", b)?; }
        Ok(())
    }
}

const LEAF_TAG: u8 = 0x00;
const NODE_TAG: u8 = 0x01;

#[derive(Debug, Clone, Copy, Default)]
struct Sha256Hasher;

impl MerkleHasher for Sha256Hasher {
    type Digest = Hash32;

    fn leaf<T: Serialize>(item: &T) -> Self::Digest {
        let enc = bincode::serialize(item).expect("serialize");
        let mut buf = Vec::with_capacity(1 + enc.len());
        buf.push(LEAF_TAG);
        buf.extend_from_slice(&enc);
        let mut h = Sha256::new(); h.update(&buf);
        let mut out = [0u8; 32]; out.copy_from_slice(&h.finalize());
        Hash32(out)
    }

    fn node(left: &Self::Digest, right: &Self::Digest) -> Self::Digest {
        let mut buf = [0u8; 1 + 32 + 32];
        buf[0] = NODE_TAG;
        buf[1..33].copy_from_slice(&left.0);
        buf[33..].copy_from_slice(&right.0);
        let mut h = Sha256::new(); h.update(&buf);
        let mut out = [0u8; 32]; out.copy_from_slice(&h.finalize());
        Hash32(out)
    }
}

type PersonMerkle = StaticMerkleArray<Person, Sha256Hasher>;

fn example_person_sha256() {
    let people = vec![
        Person { id: 1, name: "Ada".into() },
        Person { id: 2, name: "Grace".into() },
        Person { id: 3, name: "Edsger".into() },
    ];

    let tree = PersonMerkle::new(people.clone());
    let proof = tree.prove_index(2).unwrap();
    assert!(verify_value_with_proof(&people[2], &proof));
}
```

> Swap `Sha256` for another hash (e.g., BLAKE3) if you prefer. Just keep the domain separation and a fixed‑size digest type that implements the trait bounds.

---

## Persistence (save / load)

Any `StaticMerkleArray<T, H>` can be serialized via `bincode`:

```rust
let path = std::env::temp_dir().join("my_tree.bin");
my_tree.save_to_file(&path).unwrap();
let restored: StaticMerkleArray<T, H> = StaticMerkleArray::load_from_file(&path).unwrap();
assert_eq!(restored.root(), my_tree.root());
```

- The on‑disk encoding contains the original `items`, the full `levels`, and the `index_map` necessary to support duplicate values and by‑value proofs.
- Cross‑version compatibility depends on your `T` and `H::Digest`’s serde representation.

---

## Proofs

```rust
// A Merkle proof for a single element
pub struct MerkleProof<H: MerkleHasher> {
    pub index: usize,
    pub siblings: Vec<(H::Digest, Side)>,
    pub root: H::Digest,
    pub leaf: H::Digest,
}

impl<H: MerkleHasher> MerkleProof<H> {
    pub fn verify(&self) -> bool { /* recompute up to root */ }
}

// Convenience helper
pub fn verify_value_with_proof<T, H>(value: &T, proof: &MerkleProof<H>) -> bool
where
    T: Serialize + DeserializeOwned,
    H: MerkleHasher,
{ /* H::leaf(value) == proof.leaf && proof.verify() */ }
```

- `prove_index(i)` walks from the leaf at `i` to the root, collecting sibling hashes and their side (left/right).
- `prove_item(value, occurrence)` selects the `occurrence`‑th position of `value` (if duplicates exist) and returns the corresponding index proof.

---

## Design notes & tips

- **Domain separation:** Always prefix leaves and nodes differently (e.g., a tag byte or a field element constant) to avoid structural collisions.
- **Duplicates:** Supported. `index_map` stores all positions for a given leaf digest.
- **Padding:** If a level has odd length, the last node is duplicated before combining. This is standard and keeps the tree complete.
- **Digest type:** `[u8; 32]` is convenient (serde‑friendly, `Copy`, `Hash`). Newtypes work too.
- **Security:** MiMC parameters here are standard for x⁷/91 on BN254; for interop with other stacks, ensure you’re using matching constants, rounding schedule, and domain tags.

---

## Run tests

```bash
cargo test -q
```

Look for tests such as:
- SHA‑256 based quick checks (array of integers)
- MiMC/BN254 `ProductionRule` tests
- Persistence round‑trip tests (save → load → verify)

---

### License / Contributions

TBD. PRs welcome for additional hashers, examples, and feature flags (e.g., `no_std`).

