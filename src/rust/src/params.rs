// Copyright (c) 2024 The Kerrigan developers
// Distributed under the MIT software license.

use memuse::DynamicUsage;
use zcash_protocol::{
    consensus::{self, BlockHeight, NetworkType},
    local_consensus::{self, LocalNetwork},
};

/// Chain parameters for the networks supported by Kerrigan.
///
/// Kerrigan must not reuse Zcash's hardcoded `consensus::Network::{MainNetwork,
/// TestNetwork}` values directly for Sapling operations: those types bake in
/// Zcash's Canopy activation heights (1_046_400 mainnet / 1_028_500 testnet).
/// Kerrigan's Sapling FFI unconditionally constructs `Rseed::BeforeZip212`
/// notes, so if `zip212_enforcement` ever returned `GracePeriod`/`On` the
/// builder would produce notes with the wrong commitment, making outputs
/// silently unspendable. To prevent that time bomb, every Kerrigan network
/// variant uses `LocalNetwork` with Canopy explicitly pinned to `None`
/// (disabled until a future Kerrigan hard fork explicitly activates it).
#[derive(Clone, Copy)]
pub(crate) enum Network {
    /// Kerrigan mainnet/testnet/devnet: uses `LocalNetwork` for activation
    /// heights (so Canopy stays disabled) while reporting the correct
    /// `NetworkType` for address encoding and HRP selection.
    Kerrigan {
        net_type: NetworkType,
        local: LocalNetwork,
    },
    /// Kerrigan regtest.
    RegTest(local_consensus::LocalNetwork),
}

impl DynamicUsage for Network {
    fn dynamic_usage(&self) -> usize {
        0
    }

    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        (0, Some(0))
    }
}

/// Constructs a `Network` from the given network string.
///
/// All activation heights are supplied by the C++ caller (from
/// `Consensus::Params`). Pass `-1` for "not activated" (encoded as
/// `Option::None` in the underlying `LocalNetwork`).
///
/// Canopy and every NU beyond Sapling MUST be passed as `-1` (None) by the
/// C++ caller until Kerrigan explicitly activates a Canopy-equivalent hard
/// fork. The ZIP-212 time bomb relies on Canopy being disabled: as long as
/// `params.activation_height(Canopy)` returns `None`, `zip212_enforcement()`
/// returns `Zip212Enforcement::Off`, which is what the `BeforeZip212` rseed
/// path in `sapling.rs` requires.
#[allow(clippy::too_many_arguments)]
pub(crate) fn network(
    network: &str,
    overwinter: i32,
    sapling: i32,
    blossom: i32,
    heartwood: i32,
    canopy: i32,
    nu5: i32,
    nu6: i32,
    nu6_1: i32,
) -> Result<Box<Network>, &'static str> {
    let i32_to_optional_height = |n: i32| {
        if n.is_negative() {
            None
        } else {
            Some(BlockHeight::from_u32(n.unsigned_abs()))
        }
    };

    let local = LocalNetwork {
        overwinter: i32_to_optional_height(overwinter),
        sapling: i32_to_optional_height(sapling),
        blossom: i32_to_optional_height(blossom),
        heartwood: i32_to_optional_height(heartwood),
        canopy: i32_to_optional_height(canopy),
        nu5: i32_to_optional_height(nu5),
        nu6: i32_to_optional_height(nu6),
        nu6_1: i32_to_optional_height(nu6_1),
    };

    let params = match network {
        "main" => Network::Kerrigan {
            net_type: NetworkType::Main,
            local,
        },
        "test" => Network::Kerrigan {
            net_type: NetworkType::Test,
            local,
        },
        "regtest" => Network::RegTest(local),
        _ => return Err("Unsupported network kind"),
    };

    Ok(Box::new(params))
}

impl consensus::Parameters for Network {
    fn network_type(&self) -> consensus::NetworkType {
        match self {
            Self::Kerrigan { net_type, .. } => *net_type,
            Self::RegTest(params) => params.network_type(),
        }
    }

    fn activation_height(&self, nu: consensus::NetworkUpgrade) -> Option<consensus::BlockHeight> {
        match self {
            Self::Kerrigan { local, .. } => local.activation_height(nu),
            Self::RegTest(params) => params.activation_height(nu),
        }
    }
}
