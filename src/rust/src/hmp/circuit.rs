//! MiMC-based commitment circuit for HMP participation proofs.
//!
//! The circuit proves knowledge of secret inputs that produce a
//! specific commitment, binding the prover to a block hash and
//! chain state without revealing the secret key.
//!
//! Public inputs:
//!   - block_hash (field element)
//!   - commitment (MiMC hash output)
//!
//! Private inputs:
//!   - sk_scalar (secret key material)
//!   - chain_state_hash (chain tip hash)
//!
//! Constraint count: ~185 R1CS constraints
//!   - 1 multiplication (sk × block_hash)
//!   - 1 addition enforcement (mixed = inner + chain_state)
//!   - 91 × 2 MiMC round constraints (square + cube)
//!   - 1 public input exposure

use bellman::{Circuit, ConstraintSystem, SynthesisError};
use bellman::gadgets::num::AllocatedNum;
use bls12_381::Scalar;
// Field trait used by bellman's AllocatedNum operations internally

/// Number of MiMC rounds. For 128-bit security on the BLS12-381
/// scalar field (~255 bits), 91 rounds of x^3 is sufficient.
const MIMC_ROUNDS: usize = 91;

/// Generate deterministic MiMC round constants.
/// Derived from sequential integers with domain separator "SCP".
fn mimc_constants() -> Vec<Scalar> {
    (0..MIMC_ROUNDS)
        .map(|i| {
            let mut wide = [0u8; 64];
            wide[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            // Domain separator "SCP" is retained from the original implementation.
            // Changing to "HMP" would alter all MiMC round constants and invalidate
            // existing proofs -- any change requires a consensus activation height.
            wide[8] = b'S';
            wide[9] = b'C';
            wide[10] = b'P';
            Scalar::from_bytes_wide(&wide)
        })
        .collect()
}

/// MiMC permutation: x → (x + c_0)^3 → (x + c_1)^3 → ... → (x + c_{r-1})^3
fn mimc_plain(input: &Scalar, constants: &[Scalar]) -> Scalar {
    let mut x = *input;
    for c in constants {
        let t = x + c;
        x = t.square() * t; // t^3
    }
    x
}

/// Compute the commitment value outside of a circuit (plain computation).
/// commitment = MiMC(sk × block_hash + chain_state)
pub fn compute_commitment(sk: &Scalar, block_hash: &Scalar, chain_state: &Scalar) -> Scalar {
    let inner = *sk * block_hash;
    let mixed = inner + chain_state;
    let constants = mimc_constants();
    mimc_plain(&mixed, &constants)
}

/// HMP participation proof circuit.
pub struct HMPCircuit {
    pub sk_scalar: Option<Scalar>,
    pub block_hash: Option<Scalar>,
    pub chain_state_hash: Option<Scalar>,
}

impl Circuit<Scalar> for HMPCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        // Allocate private input: secret key material
        let sk = AllocatedNum::alloc(cs.namespace(|| "sk"), || {
            self.sk_scalar
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate block hash as private first, then expose as public input
        let block_hash = AllocatedNum::alloc(cs.namespace(|| "block_hash"), || {
            self.block_hash
                .ok_or(SynthesisError::AssignmentMissing)
        })?;
        block_hash.inputize(cs.namespace(|| "block_hash_input"))?;

        // Allocate private input: chain state hash
        let chain_state = AllocatedNum::alloc(cs.namespace(|| "chain_state"), || {
            self.chain_state_hash
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Step 1: inner = sk × block_hash (binds secret key to this block)
        let inner = sk.mul(cs.namespace(|| "sk_mul_block"), &block_hash)?;

        // Step 2: mixed = inner + chain_state (binds to chain observation)
        let mixed = AllocatedNum::alloc(cs.namespace(|| "mixed"), || {
            let a = inner
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?;
            let b = chain_state
                .get_value()
                .ok_or(SynthesisError::AssignmentMissing)?;
            Ok(a + b)
        })?;
        cs.enforce(
            || "mixed_eq",
            |lc| lc + inner.get_variable() + chain_state.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + mixed.get_variable(),
        );

        // Step 3: Apply MiMC permutation
        let constants = mimc_constants();
        let result = mimc_gadget(cs, &mixed, &constants)?;

        // Expose commitment as public input
        result.inputize(cs.namespace(|| "commitment"))?;

        Ok(())
    }
}

/// MiMC permutation as a circuit gadget.
/// Each round: x → (x + c_i)^3 using 2 R1CS constraints.
fn mimc_gadget<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    input: &AllocatedNum<Scalar>,
    constants: &[Scalar],
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    let mut xl = input.clone();

    for (i, c) in constants.iter().enumerate() {
        // Compute (xl + c)^2
        let sq = {
            let sq_val = xl.get_value().map(|x| {
                let t = x + c;
                t.square()
            });
            let sq = AllocatedNum::alloc(cs.namespace(|| format!("sq_{}", i)), || {
                sq_val.ok_or(SynthesisError::AssignmentMissing)
            })?;
            // Enforce: (xl + c) * (xl + c) = sq
            cs.enforce(
                || format!("sq_c_{}", i),
                |lc| lc + xl.get_variable() + (*c, CS::one()),
                |lc| lc + xl.get_variable() + (*c, CS::one()),
                |lc| lc + sq.get_variable(),
            );
            sq
        };

        // Compute (xl + c)^3 = sq * (xl + c)
        let cube = {
            let cube_val = xl.get_value().map(|x| {
                let t = x + c;
                t.square() * t
            });
            let cube = AllocatedNum::alloc(cs.namespace(|| format!("cb_{}", i)), || {
                cube_val.ok_or(SynthesisError::AssignmentMissing)
            })?;
            // Enforce: sq * (xl + c) = cube
            cs.enforce(
                || format!("cb_c_{}", i),
                |lc| lc + sq.get_variable(),
                |lc| lc + xl.get_variable() + (*c, CS::one()),
                |lc| lc + cube.get_variable(),
            );
            cube
        };

        xl = cube;
    }

    Ok(xl)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellman::groth16;
    use rand_core::OsRng;

    #[test]
    fn test_commitment_deterministic() {
        let sk = Scalar::from(42u64);
        let block = Scalar::from(100u64);
        let chain = Scalar::from(200u64);

        let c1 = compute_commitment(&sk, &block, &chain);
        let c2 = compute_commitment(&sk, &block, &chain);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_commitment_changes_with_input() {
        let sk = Scalar::from(42u64);
        let block = Scalar::from(100u64);
        let chain1 = Scalar::from(200u64);
        let chain2 = Scalar::from(201u64);

        let c1 = compute_commitment(&sk, &block, &chain1);
        let c2 = compute_commitment(&sk, &block, &chain2);
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_proof_roundtrip() {
        // Generate parameters
        let dummy = HMPCircuit {
            sk_scalar: None,
            block_hash: None,
            chain_state_hash: None,
        };
        let params =
            groth16::generate_random_parameters::<bls12_381::Bls12, _, _>(dummy, &mut OsRng)
                .unwrap();
        let pvk = groth16::prepare_verifying_key(&params.vk);

        // Create proof with real inputs
        let sk = Scalar::from(42u64);
        let block = Scalar::from(100u64);
        let chain = Scalar::from(200u64);
        let commitment = compute_commitment(&sk, &block, &chain);

        let circuit = HMPCircuit {
            sk_scalar: Some(sk),
            block_hash: Some(block),
            chain_state_hash: Some(chain),
        };

        let proof = groth16::create_random_proof(circuit, &params, &mut OsRng).unwrap();

        // Verify with correct public inputs
        let public_inputs = vec![block, commitment];
        assert!(groth16::verify_proof(&pvk, &proof, &public_inputs).is_ok());

        // Verify with wrong commitment fails
        let wrong_commitment = Scalar::from(999u64);
        let wrong_inputs = vec![block, wrong_commitment];
        assert!(groth16::verify_proof(&pvk, &proof, &wrong_inputs).is_err());
    }
}
