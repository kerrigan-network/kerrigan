//! Hivemind Protocol (HMP) — Groth16 participation proofs.
//!
//! Proves honest participation in the sealing protocol using zk-SNARKs
//! on BLS12-381 (same curve as Sapling). Uses a MiMC-based commitment
//! circuit with ~185 R1CS constraints.

pub mod circuit;

use bellman::groth16::{self, Parameters, PreparedVerifyingKey, Proof};
use bls12_381::Scalar;
use group::ff::PrimeField;
use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, SeedableRng};
use sha2::{Sha256, Sha512, Digest};
use std::io::Cursor;
use std::sync::OnceLock;

use circuit::HMPCircuit;

// Groth16 parameters generated via deterministic trusted setup at daemon init.
// Small circuit (~185 constraints) so generation is fast (<1s).
//
// CONSENSUS-CRITICAL: All nodes must generate identical CRS parameters.
// We use a deterministic RNG seeded from a fixed domain separator so every
// node produces the same parameters.  This is a "nothing-up-my-sleeve"
// deterministic setup — the seed is public and verifiable.
//
// Phase 2 plan (#397): Replace Groth16 entirely with a transparent proof
// system (PLONK or Halo2) that requires no trusted setup.  Until then,
// nHMPMandatoryProofHeight = 0 on all networks means proofs are accepted
// but never required, so this deterministic CRS is sufficient.
static HMP_PARAMS: OnceLock<Parameters<bls12_381::Bls12>> = OnceLock::new();
static HMP_VK: OnceLock<PreparedVerifyingKey<bls12_381::Bls12>> = OnceLock::new();

/// Initialize HMP Groth16 parameters (deterministic trusted setup).
/// Generates parameters using a deterministic RNG seeded from a fixed
/// consensus value, ensuring all nodes produce identical CRS parameters.
/// Must be called once at daemon startup.
pub fn init_hmp_params() -> Result<(), String> {
    let dummy = HMPCircuit {
        sk_scalar: None,
        block_hash: None,
        chain_state_hash: None,
    };

    // Deterministic seed: SHA-256 of a fixed domain separator.
    // Every node computes the same seed → same CRS → proofs are cross-node verifiable.
    // This will be replaced with a transparent setup (PLONK/Halo2) in Phase 2.
    let seed: [u8; 32] = Sha256::digest(b"kerrigan-hmp-groth16-v1").into();
    let mut rng = ChaCha20Rng::from_seed(seed);

    let params = groth16::generate_random_parameters::<bls12_381::Bls12, _, _>(
        dummy, &mut rng,
    )
    .map_err(|e| format!("HMP param generation failed: {:?}", e))?;

    let vk = groth16::prepare_verifying_key(&params.vk);

    let _ = HMP_PARAMS.set(params);
    let _ = HMP_VK.set(vk);

    Ok(())
}

/// Returns true if HMP Groth16 parameters have been initialized.
pub fn is_hmp_initialized() -> bool {
    HMP_PARAMS.get().is_some() && HMP_VK.get().is_some()
}

/// Create a Groth16 participation proof.
///
/// # Arguments
/// * `sk_bytes` — 32 bytes of secret key material
/// * `block_hash` — the block being sealed
/// * `chain_state_hash` — hash of chain state at signing time
///
/// # Returns
/// 192-byte Groth16 proof (48 + 96 + 48 bytes for G1, G2, G1 on BLS12-381)
pub fn hmp_create_proof(
    sk_bytes: &[u8; 32],
    block_hash: &[u8; 32],
    chain_state_hash: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let params = HMP_PARAMS
        .get()
        .ok_or_else(|| "HMP params not initialized".to_string())?;

    let sk_scalar = bytes_to_scalar(sk_bytes);
    let block_scalar = bytes_to_scalar(block_hash);
    let chain_scalar = bytes_to_scalar(chain_state_hash);

    let instance = HMPCircuit {
        sk_scalar: Some(sk_scalar),
        block_hash: Some(block_scalar),
        chain_state_hash: Some(chain_scalar),
    };

    let proof = groth16::create_random_proof(instance, params, &mut OsRng)
        .map_err(|e| format!("HMP proof creation failed: {:?}", e))?;

    // Serialize to bytes
    let mut buf = Vec::new();
    proof
        .write(&mut buf)
        .map_err(|e| format!("proof serialization failed: {}", e))?;

    Ok(buf)
}

/// Verify a Groth16 participation proof.
///
/// # Arguments
/// * `proof_bytes` — serialized Groth16 proof (192 bytes)
/// * `block_hash` — the block that was sealed (public input)
/// * `commitment` — the commitment value (public input)
///
/// # Returns
/// true if the proof is valid
pub fn hmp_verify_proof(
    proof_bytes: &[u8],
    block_hash: &[u8; 32],
    commitment: &[u8; 32],
) -> Result<bool, String> {
    let vk = HMP_VK
        .get()
        .ok_or_else(|| "HMP params not initialized".to_string())?;

    let proof = Proof::read(&mut Cursor::new(proof_bytes))
        .map_err(|e| format!("proof deserialization failed: {}", e))?;

    let block_scalar = bytes_to_scalar(block_hash);

    // The commitment is already a serialized Scalar (produced by scalar_to_bytes /
    // to_repr in hmp_compute_commitment).  Deserialize it directly instead of
    // hashing through SHA-512 like raw byte inputs, which would produce a
    // completely different field element and cause every proof to fail (#1082).
    let commitment_scalar = {
        let repr = <Scalar as PrimeField>::Repr::from(*commitment);
        Option::from(Scalar::from_repr(repr))
            .ok_or_else(|| "invalid commitment scalar representation".to_string())?
    };

    let public_inputs = vec![block_scalar, commitment_scalar];

    match groth16::verify_proof(vk, &proof, &public_inputs) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Compute the commitment for given inputs.
/// Used by both prover (to include in seal share) and verifier (to check).
///
/// commitment = MiMC(sk * block_hash + chain_state)
pub fn hmp_compute_commitment(
    sk_bytes: &[u8; 32],
    block_hash: &[u8; 32],
    chain_state_hash: &[u8; 32],
) -> Result<[u8; 32], String> {
    let sk = bytes_to_scalar(sk_bytes);
    let block = bytes_to_scalar(block_hash);
    let chain = bytes_to_scalar(chain_state_hash);

    let commitment = circuit::compute_commitment(&sk, &block, &chain);
    Ok(scalar_to_bytes(&commitment))
}

/// Convert 32 bytes to a BLS12-381 scalar field element.
/// Hashes the input with SHA-512 to obtain a full 64 bytes of entropy
/// before scalar reduction, giving a uniform distribution over the field.
/// (#406: previous version zero-padded to 64 bytes, reducing the hash
/// collision domain by leaving the upper 32 bytes as zeros.)
fn bytes_to_scalar(bytes: &[u8; 32]) -> Scalar {
    let hash = Sha512::digest(bytes);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&hash);
    Scalar::from_bytes_wide(&wide)
}

/// Convert a scalar field element to 32 bytes.
fn scalar_to_bytes(s: &Scalar) -> [u8; 32] {
    s.to_repr()
}
