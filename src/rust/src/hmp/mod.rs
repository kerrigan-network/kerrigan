//! Hivemind Protocol (HMP) -- Groth16 participation proofs.
//!
//! Proves honest participation in the sealing protocol using zk-SNARKs
//! on BLS12-381 (same curve as Sapling). Uses a MiMC-based commitment
//! circuit with ~185 R1CS constraints.

pub mod circuit;

use bellman::groth16::{self, Parameters, PreparedVerifyingKey, Proof};
use bls12_381::Scalar;
use group::ff::PrimeField;
use rand_core::OsRng;
use sha2::{Sha512, Digest};
use std::io::Cursor;
use std::sync::OnceLock;

use circuit::HMPCircuit;

// Groth16 parameters generated once with real entropy (OsRng) and cached
// to disk.  The cached file is keyed to the circuit structure so it is
// safe to reuse across daemon restarts on the same machine.
//
// Cross-machine verification: since each machine generates its own CRS,
// proofs from one node will not verify on another.  This is acceptable
// because nHMPMandatoryProofHeight = 0 on all networks (empty proofs
// are always accepted).  The zk-proof is an anti-Sybil gate at the P2P
// share layer only — on-chain consensus relies on BLS aggregate signatures.
//
// Phase 2 plan (#397): Replace Groth16 entirely with a transparent proof
// system (PLONK or Halo2) that requires no trusted setup.
static HMP_PARAMS: OnceLock<Parameters<bls12_381::Bls12>> = OnceLock::new();
static HMP_VK: OnceLock<PreparedVerifyingKey<bls12_381::Bls12>> = OnceLock::new();

/// Returns the path for the cached HMP Groth16 parameters file.
/// Override via HMP_PARAMS_PATH environment variable.
fn params_cache_path() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("HMP_PARAMS_PATH") {
        return std::path::PathBuf::from(path);
    }
    let mut path = std::env::temp_dir();
    path.push("kerrigan-hmp-groth16-params-v1.bin");
    path
}

/// Initialize HMP Groth16 parameters with a one-time trusted setup.
///
/// On the first call, generates parameters using OsRng (real entropy,
/// toxic waste is truly destroyed) and caches them to disk.  Subsequent
/// calls reload the cached parameters for consistency within a machine.
///
/// Must be called once at daemon startup.
pub fn init_hmp_params() -> Result<(), String> {
    // Try loading from cache first
    let cache_path = params_cache_path();
    if let Ok(bytes) = std::fs::read(&cache_path) {
        let params = Parameters::read(&bytes[..], true)
            .map_err(|e| format!("failed to deserialize cached HMP params: {}", e))?;
        let vk = groth16::prepare_verifying_key(&params.vk);
        let _ = HMP_PARAMS.set(params);
        let _ = HMP_VK.set(vk);
        return Ok(());
    }

    // Generate parameters with real entropy — toxic waste is destroyed.
    let dummy = HMPCircuit {
        sk_scalar: None,
        block_hash: None,
        chain_state_hash: None,
    };

    let params = groth16::generate_random_parameters::<bls12_381::Bls12, _, _>(
        dummy, &mut OsRng,
    )
    .map_err(|e| format!("HMP param generation failed: {:?}", e))?;

    // Cache to disk so future runs on this machine reuse the same params
    let mut buf = Vec::new();
    params
        .write(&mut buf)
        .map_err(|e| format!("HMP param serialization failed: {}", e))?;
    let _ = std::fs::write(&cache_path, &buf);

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
/// * `sk_bytes` -- 32 bytes of secret key material
/// * `block_hash` -- the block being sealed
/// * `chain_state_hash` -- hash of chain state at signing time
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
/// * `proof_bytes` -- serialized Groth16 proof (192 bytes)
/// * `block_hash` -- the block that was sealed (public input)
/// * `commitment` -- the commitment value (public input)
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
