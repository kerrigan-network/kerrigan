// Copyright (c) 2024 The Kerrigan developers
// Adapted from Zcash's sapling/spec.rs
// Distributed under the MIT software license.

use std::convert::TryInto;

use group::{cofactor::CofactorGroup, GroupEncoding};
use incrementalmerkletree::Hashable;
use rand_core::{OsRng, RngCore};

use sapling::{
    constants::{CRH_IVK_PERSONALIZATION, PROOF_GENERATION_KEY_GENERATOR, SPENDING_KEY_GENERATOR},
    merkle_hash,
    note::{ExtractedNoteCommitment, NoteCommitment},
    value::NoteValue,
    Diversifier, Node, Note, NullifierDerivingKey, PaymentAddress, Rseed,
};
use zcash_primitives::merkle_tree::HashSer;

use crate::de_ct;

#[cxx::bridge]
mod ffi {
    #[namespace = "sapling::spec"]
    extern "Rust" {
        fn tree_uncommitted() -> [u8; 32];
        fn merkle_hash(depth: usize, lhs: &[u8; 32], rhs: &[u8; 32]) -> [u8; 32];
        fn to_scalar(input: &[u8; 64]) -> [u8; 32];
        fn ask_to_ak(ask: &[u8; 32]) -> Result<[u8; 32]>;
        fn nsk_to_nk(nsk: &[u8; 32]) -> Result<[u8; 32]>;
        fn crh_ivk(ak: &[u8; 32], nk: &[u8; 32]) -> [u8; 32];
        fn check_diversifier(diversifier: [u8; 11]) -> bool;
        fn ivk_to_pkd(ivk: &[u8; 32], diversifier: [u8; 11]) -> Result<[u8; 32]>;
        fn generate_r() -> [u8; 32];
        fn compute_nf(
            diversifier: &[u8; 11],
            pk_d: &[u8; 32],
            value: u64,
            rcm: &[u8; 32],
            nk: &[u8; 32],
            position: u64,
        ) -> Result<[u8; 32]>;
        fn compute_cmu(
            diversifier: [u8; 11],
            pk_d: &[u8; 32],
            value: u64,
            rcm: &[u8; 32],
        ) -> Result<[u8; 32]>;
    }
}

fn fixed_scalar_mult(
    from: &[u8; 32],
    p_g: &jubjub::SubgroupPoint,
) -> Result<jubjub::SubgroupPoint, String> {
    let f = de_ct(jubjub::Fr::from_bytes(from))
        .ok_or_else(|| "Invalid scalar bytes for fixed_scalar_mult".to_string())?;
    Ok(p_g * f)
}

fn tree_uncommitted() -> [u8; 32] {
    let mut result = [0; 32];
    Node::empty_leaf()
        .write(&mut result[..])
        .expect("Sapling leaves are 32 bytes");
    result
}

fn to_scalar(input: &[u8; 64]) -> [u8; 32] {
    jubjub::Scalar::from_bytes_wide(input).to_bytes()
}

pub(crate) fn ask_to_ak(ask: &[u8; 32]) -> Result<[u8; 32], String> {
    let ak = fixed_scalar_mult(ask, &SPENDING_KEY_GENERATOR)?;
    Ok(ak.to_bytes())
}

pub(crate) fn nsk_to_nk(nsk: &[u8; 32]) -> Result<[u8; 32], String> {
    let nk = fixed_scalar_mult(nsk, &PROOF_GENERATION_KEY_GENERATOR)?;
    Ok(nk.to_bytes())
}

pub(crate) fn crh_ivk(ak: &[u8; 32], nk: &[u8; 32]) -> [u8; 32] {
    let mut h = blake2s_simd::Params::new()
        .hash_length(32)
        .personal(CRH_IVK_PERSONALIZATION)
        .to_state();
    h.update(ak);
    h.update(nk);
    // BLAKE2s with hash_length(32) always produces exactly 32 bytes; the
    // try_into() cannot fail — use expect to keep this explicit.
    let mut h: [u8; 32] = h
        .finalize()
        .as_ref()
        .try_into()
        .expect("BLAKE2s output is always 32 bytes");

    // Drop the last five bits, so it can be interpreted as a scalar.
    h[31] &= 0b0000_0111;

    h
}

pub(crate) fn check_diversifier(diversifier: [u8; 11]) -> bool {
    let diversifier = Diversifier(diversifier);
    diversifier.g_d().is_some()
}

pub(crate) fn ivk_to_pkd(ivk: &[u8; 32], diversifier: [u8; 11]) -> Result<[u8; 32], String> {
    let ivk = de_ct(jubjub::Scalar::from_bytes(ivk));
    let diversifier = Diversifier(diversifier);
    if let (Some(ivk), Some(g_d)) = (ivk, diversifier.g_d()) {
        let pk_d = g_d * ivk;
        Ok(pk_d.to_bytes())
    } else {
        Err("Diversifier is invalid".to_owned())
    }
}

fn generate_r() -> [u8; 32] {
    let mut rng = OsRng;
    let mut buffer = [0u8; 64];
    rng.fill_bytes(&mut buffer);

    let r = jubjub::Scalar::from_bytes_wide(&buffer);
    r.to_bytes()
}

fn priv_get_note(
    diversifier: &[u8; 11],
    pk_d: &[u8; 32],
    value: u64,
    rcm: &[u8; 32],
) -> Result<Note, String> {
    let recipient_bytes = {
        let mut tmp = [0; 43];
        tmp[..11].copy_from_slice(&diversifier[..]);
        tmp[11..].copy_from_slice(&pk_d[..]);
        tmp
    };
    let recipient = PaymentAddress::from_bytes(&recipient_bytes)
        .ok_or_else(|| "Invalid recipient encoding".to_string())?;

    let rseed = Rseed::BeforeZip212(
        de_ct(jubjub::Scalar::from_bytes(rcm)).ok_or_else(|| "Invalid rcm encoding".to_string())?,
    );

    Ok(Note::from_parts(
        recipient,
        NoteValue::from_raw(value),
        rseed,
    ))
}

pub(crate) fn compute_nf(
    diversifier: &[u8; 11],
    pk_d: &[u8; 32],
    value: u64,
    rcm: &[u8; 32],
    nk: &[u8; 32],
    position: u64,
) -> Result<[u8; 32], String> {
    let note = priv_get_note(diversifier, pk_d, value, rcm)?;

    let nk = match de_ct(jubjub::ExtendedPoint::from_bytes(nk)) {
        Some(p) => p,
        None => return Err("Invalid nk encoding".to_owned()),
    };

    let nk = match de_ct(nk.into_subgroup()) {
        Some(nk) => NullifierDerivingKey(nk),
        None => return Err("nk is not in the prime-order subgroup".to_owned()),
    };

    let nf = note.nf(&nk, position);
    Ok(nf.0)
}

pub(crate) fn compute_cmu(
    diversifier: [u8; 11],
    pk_d: &[u8; 32],
    value: u64,
    rcm: &[u8; 32],
) -> Result<[u8; 32], String> {
    let diversifier = Diversifier(diversifier);
    let g_d = diversifier
        .g_d()
        .ok_or_else(|| "Invalid diversifier".to_string())?;

    let pk_d =
        de_ct(jubjub::ExtendedPoint::from_bytes(pk_d)).ok_or_else(|| "Invalid pk_d".to_string())?;
    let pk_d = de_ct(pk_d.into_subgroup())
        .ok_or_else(|| "pk_d is not in the prime-order subgroup".to_string())?;

    let rcm = de_ct(jubjub::Scalar::from_bytes(rcm)).ok_or_else(|| "Invalid rcm".to_string())?;

    let cmu = ExtractedNoteCommitment::from(NoteCommitment::temporary_zcashd_derive(
        g_d.to_bytes(),
        pk_d.to_bytes(),
        NoteValue::from_raw(value),
        rcm,
    ));

    Ok(cmu.to_bytes())
}
