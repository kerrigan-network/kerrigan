//! FFI between the C++ Kerrigan codebase and the Rust Sapling crates.
//!
//! This is internal to kerrigand and is not an officially-supported API.

#![deny(broken_intra_doc_links)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use ::sapling::circuit::{
    OutputParameters, OutputVerifyingKey, SpendParameters, SpendVerifyingKey,
};
use std::sync::OnceLock;
use subtle::CtOption;

mod bridge;
mod bundlecache;
mod merkle_tree;
mod note_encryption;
mod params;
mod sapling;
pub mod hmp;
mod streams;

static SAPLING_SPEND_VK: OnceLock<SpendVerifyingKey> = OnceLock::new();
static SAPLING_OUTPUT_VK: OnceLock<OutputVerifyingKey> = OnceLock::new();

static SAPLING_SPEND_PARAMS: OnceLock<SpendParameters> = OnceLock::new();
static SAPLING_OUTPUT_PARAMS: OnceLock<OutputParameters> = OnceLock::new();

/// Initialize Sapling zk-SNARK parameters from files on disk.
///
/// Loads the spend and output parameter files, verifies their integrity
/// (size + BLAKE2b hash), deserializes the proving parameters, and extracts
/// verifying keys. Stores everything in the module-level statics so that
/// the prover and verifier can use them.
///
/// Must be called exactly once, before any Sapling proof creation or
/// verification. Thread-safe: OnceLock guarantees at-most-once initialization.
pub fn init_sapling_params(spend_path: &str, output_path: &str) -> Result<(), String> {
    let spend = std::path::Path::new(spend_path);
    let output = std::path::Path::new(output_path);

    if !spend.exists() {
        return Err(format!("Sapling spend params not found: {}", spend_path));
    }
    if !output.exists() {
        return Err(format!("Sapling output params not found: {}", output_path));
    }

    // load_parameters verifies file sizes and BLAKE2b hashes, then
    // deserializes the Groth16 parameters. It will panic on corrupt files
    // (hash mismatch), which is the correct behaviour — we must not proceed
    // with bad parameters.
    let loaded = zcash_proofs::load_parameters(spend, output, None);

    // OnceLock::set returns Err if already initialized; ignore the duplicate
    // since the values would be identical (same files, same hashes).
    let _ = SAPLING_SPEND_VK.set(loaded.spend_params.verifying_key());
    let _ = SAPLING_OUTPUT_VK.set(loaded.output_params.verifying_key());
    let _ = SAPLING_SPEND_PARAMS.set(loaded.spend_params);
    let _ = SAPLING_OUTPUT_PARAMS.set(loaded.output_params);

    Ok(())
}

/// Returns true if Sapling parameters have been loaded.
pub fn is_sapling_initialized() -> bool {
    SAPLING_SPEND_VK.get().is_some() && SAPLING_OUTPUT_VK.get().is_some()
}

/// Converts CtOption<T> into Option<T>
fn de_ct<T>(ct: CtOption<T>) -> Option<T> {
    if ct.is_some().into() {
        Some(ct.unwrap())
    } else {
        None
    }
}

const GROTH_PROOF_SIZE: usize = 48 // π_A
    + 96 // π_B
    + 48; // π_C
