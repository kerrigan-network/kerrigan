//! Incremental Merkle tree for Sapling note commitments.
//!
//! Wraps `incrementalmerkletree` types behind CXX-friendly opaque wrappers:
//!
//! - **SaplingFrontier** — lightweight frontier for consensus tree root tracking.
//!   Stores only O(log n) data, sufficient to compute roots and append leaves.
//!   Used by CSaplingState to maintain the global commitment tree.
//!
//! - **SaplingWitness** — per-note incremental witness for spending.
//!   Tracks the authentication path for a specific note, updated incrementally
//!   as new commitments are appended. Produces the 1065-byte Merkle path
//!   required by the Sapling prover.

use byteorder::{LittleEndian, WriteBytesExt};
use incrementalmerkletree::frontier::CommitmentTree;
use incrementalmerkletree::witness::IncrementalWitness;
use sapling::Node;
use zcash_primitives::merkle_tree::{
    read_commitment_tree, read_incremental_witness, write_commitment_tree,
    write_incremental_witness, HashSer,
};

/// Depth of the Sapling note commitment tree.
pub const SAPLING_TREE_DEPTH: u8 = 32;

/// 1 byte depth + 32 × (1 byte len + 32 bytes hash) + 8 bytes position.
const MERKLE_PATH_BYTES: usize = 1 + 33 * (SAPLING_TREE_DEPTH as usize) + 8;

// --- Frontier (consensus) -------------------------------------------------

/// Opaque Sapling commitment tree frontier for CXX bridge.
pub struct SaplingFrontier {
    inner: CommitmentTree<Node, SAPLING_TREE_DEPTH>,
}

/// Create a new empty Sapling commitment tree frontier.
pub fn new_sapling_frontier() -> Box<SaplingFrontier> {
    Box::new(SaplingFrontier {
        inner: CommitmentTree::empty(),
    })
}

/// Append a note commitment (cmu) to the frontier.
pub fn frontier_append(tree: &mut SaplingFrontier, cmu: &[u8; 32]) -> Result<(), String> {
    let node = Node::read(&cmu[..]).map_err(|e| format!("Invalid cmu: {}", e))?;
    tree.inner
        .append(node)
        .map_err(|_| "Tree is full (2^32 leaves)".to_string())
}

/// Get the Merkle root hash of the frontier.
pub fn frontier_root(tree: &SaplingFrontier) -> [u8; 32] {
    let root = tree.inner.root();
    let mut buf = [0u8; 32];
    root.write(&mut buf[..]).expect("Node serializes to 32 bytes");
    buf
}

/// Number of leaves appended to the tree.
pub fn frontier_size(tree: &SaplingFrontier) -> u64 {
    tree.inner.size() as u64
}

/// Serialize the frontier to a byte vector for LevelDB storage.
pub fn frontier_serialize(tree: &SaplingFrontier) -> Vec<u8> {
    let mut buf = Vec::new();
    write_commitment_tree(&tree.inner, &mut buf).expect("serialization should not fail");
    buf
}

/// Deserialize a frontier from bytes.
pub fn frontier_deserialize(data: &[u8]) -> Result<Box<SaplingFrontier>, String> {
    if data.is_empty() {
        return Ok(new_sapling_frontier());
    }
    let inner: CommitmentTree<Node, SAPLING_TREE_DEPTH> =
        read_commitment_tree(&data[..]).map_err(|e| format!("Failed to deserialize frontier: {}", e))?;
    Ok(Box::new(SaplingFrontier { inner }))
}

// --- Witness (wallet) -----------------------------------------------------

/// Opaque per-note incremental witness for CXX bridge.
pub struct SaplingWitness {
    inner: IncrementalWitness<Node, SAPLING_TREE_DEPTH>,
}

/// Create a witness from the current frontier state.
///
/// The witness tracks the authentication path for the most recently appended
/// leaf. Call this immediately after appending the note you want to spend.
pub fn witness_from_frontier(tree: &SaplingFrontier) -> Result<Box<SaplingWitness>, String> {
    let witness = IncrementalWitness::from_tree(tree.inner.clone())
        .ok_or("Cannot create witness from empty tree")?;
    Ok(Box::new(SaplingWitness { inner: witness }))
}

/// Update the witness with a new note commitment appended to the global tree.
///
/// Must be called for every commitment appended after the witnessed note,
/// in order. Failing to update makes the witness stale and unusable.
pub fn witness_append(wit: &mut SaplingWitness, cmu: &[u8; 32]) -> Result<(), String> {
    let node = Node::read(&cmu[..]).map_err(|e| format!("Invalid cmu: {}", e))?;
    wit.inner
        .append(node)
        .map_err(|_| "Witness tree is full".to_string())
}

/// Get the Merkle root from the witness's perspective.
pub fn witness_root(wit: &SaplingWitness) -> [u8; 32] {
    let root = wit.inner.root();
    let mut buf = [0u8; 32];
    root.write(&mut buf[..]).expect("Node serializes to 32 bytes");
    buf
}

/// Get the position of the witnessed leaf.
pub fn witness_position(wit: &SaplingWitness) -> u64 {
    u64::from(wit.inner.witnessed_position())
}

/// Get the 1065-byte Merkle path for the Sapling prover.
///
/// Format: [depth: u8] [32 × (len: u8, hash: [u8; 32])] [position: u64 LE]
///
/// The path elements are written shallowest-first (root-1 down to leaf sibling)
/// to match the format expected by `merkle_path_from_slice`.
pub fn witness_path(wit: &SaplingWitness) -> Result<[u8; MERKLE_PATH_BYTES], String> {
    let merkle_path = wit
        .inner
        .path()
        .ok_or("Witness has no path (tree may be empty or corrupted)")?;

    let elems = merkle_path.path_elems();
    if elems.len() != SAPLING_TREE_DEPTH as usize {
        return Err(format!(
            "Expected {} path elements, got {}",
            SAPLING_TREE_DEPTH,
            elems.len()
        ));
    }

    let mut buf = [0u8; MERKLE_PATH_BYTES];
    let mut cursor = &mut buf[..];

    // Depth byte
    cursor[0] = SAPLING_TREE_DEPTH;
    cursor = &mut cursor[1..];

    // Path elements in reverse order (shallowest first in wire format).
    // path_elems()[0] is the deepest (leaf sibling), written last.
    for elem in elems.iter().rev() {
        cursor[0] = 32; // length of hash
        elem.write(&mut cursor[1..33])
            .map_err(|e| format!("Failed to write path element: {}", e))?;
        cursor = &mut cursor[33..];
    }

    // Position as u64 LE
    cursor
        .write_u64::<LittleEndian>(u64::from(merkle_path.position()))
        .map_err(|e| format!("Failed to write position: {}", e))?;

    Ok(buf)
}

/// Serialize the witness for wallet storage.
pub fn witness_serialize(wit: &SaplingWitness) -> Vec<u8> {
    let mut buf = Vec::new();
    write_incremental_witness(&wit.inner, &mut buf).expect("serialization should not fail");
    buf
}

/// Deserialize a witness from bytes.
pub fn witness_deserialize(data: &[u8]) -> Result<Box<SaplingWitness>, String> {
    let inner: IncrementalWitness<Node, SAPLING_TREE_DEPTH> = read_incremental_witness(&data[..])
        .map_err(|e| format!("Failed to deserialize witness: {}", e))?;
    Ok(Box::new(SaplingWitness { inner }))
}
