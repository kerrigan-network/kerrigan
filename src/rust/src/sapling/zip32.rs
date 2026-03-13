// Copyright (c) 2024 The Kerrigan developers
// Adapted from Zcash's sapling/zip32.rs
// Distributed under the MIT software license.

use sapling::{
    keys::FullViewingKey,
    zip32::{sapling_address, sapling_derive_internal_fvk, sapling_find_address},
    Diversifier,
};

use crate::bridge::ffi as bridge_ffi;

pub(crate) fn xsk_master(seed: &[u8]) -> Result<[u8; 169], String> {
    let xsk = sapling::zip32::ExtendedSpendingKey::master(seed);

    let mut xsk_master = [0; 169];
    xsk.write(&mut xsk_master[..])
        .map_err(|e| format!("Failed to serialize master ExtendedSpendingKey: {}", e))?;
    Ok(xsk_master)
}

pub(crate) fn xsk_derive(xsk_parent: &[u8; 169], i: u32) -> Result<[u8; 169], String> {
    let xsk_parent = sapling::zip32::ExtendedSpendingKey::read(&xsk_parent[..])
        .map_err(|e| format!("Invalid ExtendedSpendingKey: {}", e))?;
    let i = zip32::ChildIndex::from_index(i)
        .ok_or_else(|| format!("Non-hardened child index {} is unsupported", i))?;

    let xsk = xsk_parent.derive_child(i);

    let mut xsk_i = [0; 169];
    xsk.write(&mut xsk_i[..])
        .map_err(|e| format!("Failed to serialize derived ExtendedSpendingKey: {}", e))?;
    Ok(xsk_i)
}

pub(crate) fn xsk_derive_internal(xsk_external: &[u8; 169]) -> Result<[u8; 169], String> {
    let xsk_external = sapling::zip32::ExtendedSpendingKey::read(&xsk_external[..])
        .map_err(|e| format!("Invalid ExtendedSpendingKey: {}", e))?;

    let xsk_internal = xsk_external.derive_internal();

    let mut xsk_internal_ret = [0; 169];
    xsk_internal
        .write(&mut xsk_internal_ret[..])
        .map_err(|e| format!("Failed to serialize internal ExtendedSpendingKey: {}", e))?;
    Ok(xsk_internal_ret)
}

pub(crate) fn xsk_to_fvk(xsk: &[u8; 169]) -> Result<[u8; 96], String> {
    let xsk = sapling::zip32::ExtendedSpendingKey::read(&xsk[..])
        .map_err(|e| format!("Invalid ExtendedSpendingKey: {}", e))?;
    let dfvk = xsk.to_diversifiable_full_viewing_key();
    Ok(dfvk.fvk().to_bytes())
}

pub(crate) fn xsk_to_dk(xsk: &[u8; 169]) -> Result<[u8; 32], String> {
    // Use the library parser to extract DK, avoiding hardcoded byte offsets that
    // would silently break if the serialization format changes (#482).
    // DiversifiableFullViewingKey::to_bytes() layout: fvk(96) + dk(32)
    let xsk_parsed = sapling::zip32::ExtendedSpendingKey::read(&xsk[..])
        .map_err(|e| format!("Invalid ExtendedSpendingKey: {}", e))?;
    let dfvk = xsk_parsed.to_diversifiable_full_viewing_key();
    let dfvk_bytes = dfvk.to_bytes();
    let mut dk = [0u8; 32];
    dk.copy_from_slice(&dfvk_bytes[96..128]);
    Ok(dk)
}

pub(crate) fn xsk_to_ivk(xsk: &[u8; 169]) -> Result<[u8; 32], String> {
    let xsk = sapling::zip32::ExtendedSpendingKey::read(&xsk[..])
        .map_err(|e| format!("Invalid ExtendedSpendingKey: {}", e))?;
    let dfvk = xsk.to_diversifiable_full_viewing_key();
    // Derive IVK from the full viewing key using CRH_IVK
    let fvk = dfvk.fvk();
    let ivk = fvk.vk.ivk();
    Ok(ivk.to_repr())
}

pub(crate) fn xsk_to_default_address(xsk: &[u8; 169]) -> Result<[u8; 43], String> {
    let xsk = sapling::zip32::ExtendedSpendingKey::read(&xsk[..])
        .map_err(|e| format!("Invalid ExtendedSpendingKey: {}", e))?;
    let dfvk = xsk.to_diversifiable_full_viewing_key();
    let (_, addr) = dfvk.default_address();
    Ok(addr.to_bytes())
}

pub(crate) fn derive_internal_fvk(
    fvk: &[u8; 96],
    dk: [u8; 32],
) -> Result<bridge_ffi::Zip32Fvk, String> {
    let fvk = FullViewingKey::read(&fvk[..])
        .map_err(|e| format!("Invalid Sapling FullViewingKey: {}", e))?;
    let dk = sapling::zip32::DiversifierKey::from_bytes(dk);

    let (fvk_internal, dk_internal) = sapling_derive_internal_fvk(&fvk, &dk);

    Ok(bridge_ffi::Zip32Fvk {
        fvk: fvk_internal.to_bytes(),
        dk: *dk_internal.as_bytes(),
    })
}

pub(crate) fn zip32_address(fvk: &[u8; 96], dk: [u8; 32], j: [u8; 11]) -> Result<[u8; 43], String> {
    let fvk = FullViewingKey::read(&fvk[..])
        .map_err(|e| format!("Invalid Sapling FullViewingKey: {}", e))?;
    let dk = sapling::zip32::DiversifierKey::from_bytes(dk);
    let j = zip32::DiversifierIndex::from(j);

    sapling_address(&fvk, &dk, j)
        .ok_or_else(|| "Diversifier index does not produce a valid diversifier".to_string())
        .map(|addr| addr.to_bytes())
}

pub(crate) fn zip32_find_address(
    fvk: &[u8; 96],
    dk: [u8; 32],
    j: [u8; 11],
) -> Result<bridge_ffi::Zip32Address, String> {
    let fvk = FullViewingKey::read(&fvk[..])
        .map_err(|e| format!("Invalid Sapling FullViewingKey: {}", e))?;
    let dk = sapling::zip32::DiversifierKey::from_bytes(dk);
    let j = zip32::DiversifierIndex::from(j);

    sapling_find_address(&fvk, &dk, j)
        .ok_or_else(|| "No valid diversifiers at or above given index".to_string())
        .map(|(j, addr)| bridge_ffi::Zip32Address {
            j: *j.as_bytes(),
            addr: addr.to_bytes(),
        })
}

pub(crate) fn diversifier_index(dk: [u8; 32], d: [u8; 11]) -> [u8; 11] {
    let dk = sapling::zip32::DiversifierKey::from_bytes(dk);
    let diversifier = Diversifier(d);

    let j = dk.diversifier_index(&diversifier);
    *j.as_bytes()
}

pub(crate) fn fvk_to_ivk(fvk: &[u8; 96]) -> Result<[u8; 32], String> {
    let fvk = FullViewingKey::read(&fvk[..])
        .map_err(|e| format!("Invalid Sapling FullViewingKey: {}", e))?;
    let ivk = fvk.vk.ivk();
    Ok(ivk.to_repr())
}

pub(crate) fn fvk_default_address(fvk: &[u8; 96], dk: [u8; 32]) -> Result<[u8; 43], String> {
    let fvk = FullViewingKey::read(&fvk[..])
        .map_err(|e| format!("Invalid Sapling FullViewingKey: {}", e))?;
    let dk = sapling::zip32::DiversifierKey::from_bytes(dk);
    let j = zip32::DiversifierIndex::from([0u8; 11]);

    sapling_find_address(&fvk, &dk, j)
        .ok_or_else(|| "No valid default diversifier found".to_string())
        .map(|(_, addr)| addr.to_bytes())
}
