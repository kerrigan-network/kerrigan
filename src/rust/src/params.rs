// Copyright (c) 2024 The Kerrigan developers
// Distributed under the MIT software license.

use memuse::DynamicUsage;
use zcash_protocol::{
    consensus::{self, BlockHeight},
    local_consensus::{self, LocalNetwork},
};

/// Chain parameters for the networks supported by Kerrigan.
#[derive(Clone, Copy)]
pub(crate) enum Network {
    Consensus(consensus::Network),
    RegTest(local_consensus::LocalNetwork),
}

impl DynamicUsage for Network {
    fn dynamic_usage(&self) -> usize {
        match self {
            Network::Consensus(params) => params.dynamic_usage(),
            Network::RegTest { .. } => 0,
        }
    }

    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        match self {
            Network::Consensus(params) => params.dynamic_usage_bounds(),
            Network::RegTest { .. } => (0, Some(0)),
        }
    }
}

/// Constructs a `Network` from the given network string.
///
/// For Kerrigan, we use Zcash's mainnet/testnet Sapling parameters as-is,
/// since the Sapling cryptography is identical. The activation heights
/// control when Sapling features become available.
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

    let params = match network {
        "main" => Network::Consensus(consensus::Network::MainNetwork),
        "test" => Network::Consensus(consensus::Network::TestNetwork),
        "regtest" => Network::RegTest(LocalNetwork {
            overwinter: i32_to_optional_height(overwinter),
            sapling: i32_to_optional_height(sapling),
            blossom: i32_to_optional_height(blossom),
            heartwood: i32_to_optional_height(heartwood),
            canopy: i32_to_optional_height(canopy),
            nu5: i32_to_optional_height(nu5),
            nu6: i32_to_optional_height(nu6),
            nu6_1: i32_to_optional_height(nu6_1),
        }),
        _ => return Err("Unsupported network kind"),
    };

    Ok(Box::new(params))
}

impl consensus::Parameters for Network {
    fn network_type(&self) -> consensus::NetworkType {
        match self {
            Self::Consensus(params) => params.network_type(),
            Self::RegTest(params) => params.network_type(),
        }
    }

    fn activation_height(&self, nu: consensus::NetworkUpgrade) -> Option<consensus::BlockHeight> {
        match self {
            Self::Consensus(params) => params.activation_height(nu),
            Self::RegTest(params) => params.activation_height(nu),
        }
    }
}
