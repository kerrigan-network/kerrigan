/// FFI bridges between Kerrigan's C++ and Rust code for Sapling shielded transactions.
///
/// Collected into a single file because CXX doesn't allow the same Rust type
/// across multiple bridges (https://github.com/dtolnay/cxx/issues/496).
///
/// All free functions exposed to C++ via `extern "Rust"` are wrapped in
/// `std::panic::catch_unwind` so that a Rust panic is converted to an error
/// (for Result-returning functions) or a safe default (for infallible
/// signatures) instead of unwinding across the FFI boundary.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;

use crate::{
    bundlecache::init as bundlecache_init_impl,
    init_sapling_params as init_sapling_params_impl,
    is_sapling_initialized as is_sapling_initialized_impl,
    hmp::{
        init_hmp_params as init_hmp_params_impl,
        is_hmp_initialized as is_hmp_initialized_impl,
        hmp_compute_commitment as hmp_compute_commitment_impl,
        hmp_create_proof as hmp_create_proof_impl,
        hmp_verify_proof as hmp_verify_proof_impl,
    },
    merkle_tree::{
        frontier_append as frontier_append_impl,
        frontier_deserialize as frontier_deserialize_impl,
        frontier_root as frontier_root_impl,
        frontier_serialize as frontier_serialize_impl,
        frontier_size as frontier_size_impl,
        new_sapling_frontier as new_sapling_frontier_impl,
        witness_append as witness_append_impl,
        witness_deserialize as witness_deserialize_impl,
        witness_from_frontier as witness_from_frontier_impl,
        witness_path as witness_path_impl,
        witness_position as witness_position_impl,
        witness_root as witness_root_impl,
        witness_serialize as witness_serialize_impl,
        SaplingFrontier, SaplingWitness,
    },
    note_encryption::{
        try_sapling_note_decryption as try_sapling_note_decryption_impl,
        try_sapling_output_recovery as try_sapling_output_recovery_impl,
        DecryptedSaplingOutput,
    },
    params::{network as network_impl, Network},
    sapling::{
        apply_sapling_bundle_signatures as apply_sapling_bundle_signatures_impl,
        build_sapling_bundle as build_sapling_bundle_impl,
        finish_bundle_assembly as finish_bundle_assembly_impl,
        init_batch_validator as init_sapling_batch_validator_impl,
        init_verifier as init_verifier_impl,
        new_bundle_assembler as new_bundle_assembler_impl,
        new_sapling_builder as new_sapling_builder_impl,
        none_sapling_bundle as none_sapling_bundle_impl,
        parse_v4_sapling_components as parse_v4_sapling_components_impl,
        parse_v4_sapling_output as parse_v4_sapling_output_impl,
        parse_v4_sapling_spend as parse_v4_sapling_spend_impl,
        parse_v5_sapling_bundle as parse_v5_sapling_bundle_impl,
        zip32::{
            derive_internal_fvk as derive_internal_fvk_impl,
            diversifier_index as diversifier_index_impl,
            fvk_default_address as fvk_default_address_impl,
            fvk_to_ivk as fvk_to_ivk_impl,
            xsk_derive as xsk_derive_impl,
            xsk_derive_internal as xsk_derive_internal_impl,
            xsk_master as xsk_master_impl,
            xsk_to_default_address as xsk_to_default_address_impl,
            xsk_to_dk as xsk_to_dk_impl,
            xsk_to_fvk as xsk_to_fvk_impl,
            xsk_to_ivk as xsk_to_ivk_impl,
            zip32_address as zip32_address_impl,
            zip32_find_address as zip32_find_address_impl,
        },
        BatchValidator as SaplingBatchValidator, Bundle as SaplingBundle,
        BundleAssembler as SaplingBundleAssembler, Output, SaplingBuilder,
        SaplingUnauthorizedBundle, Spend, Verifier,
    },
    streams::{
        from_auto_file as from_auto_file_impl,
        from_buffered_file as from_buffered_file_impl,
        from_data as from_data_impl,
        from_hash_writer as from_hash_writer_impl,
        from_size_computer as from_size_computer_impl,
        CppStream,
    },
};

/// Convert a caught panic payload into a human-readable String.
fn panic_to_string(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        format!("Rust panic: {}", s)
    } else if let Some(s) = payload.downcast_ref::<String>() {
        format!("Rust panic: {}", s)
    } else {
        "Rust panic (unknown payload)".to_string()
    }
}

// ---------------------------------------------------------------------------
// Stream wrappers — these take Pin references that cannot panic in practice
// (they just box a wrapper struct), but we guard them anyway.
// ---------------------------------------------------------------------------

fn from_data(stream: Pin<&mut ffi::RustStream>) -> Box<CppStream<'_>> {
    // Stream constructors are infallible thin wrappers; a panic here would
    // indicate a serious internal bug, so we abort as a last resort since
    // there is no Result return to propagate to.
    match catch_unwind(AssertUnwindSafe(|| from_data_impl(stream))) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("FATAL: {}", panic_to_string(e));
            std::process::abort();
        }
    }
}

fn from_auto_file(file: Pin<&mut ffi::CAutoFile>) -> Box<CppStream<'_>> {
    match catch_unwind(AssertUnwindSafe(|| from_auto_file_impl(file))) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("FATAL: {}", panic_to_string(e));
            std::process::abort();
        }
    }
}

fn from_buffered_file(file: Pin<&mut ffi::CBufferedFile>) -> Box<CppStream<'_>> {
    match catch_unwind(AssertUnwindSafe(|| from_buffered_file_impl(file))) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("FATAL: {}", panic_to_string(e));
            std::process::abort();
        }
    }
}

fn from_hash_writer(writer: Pin<&mut ffi::CHashWriter>) -> Box<CppStream<'_>> {
    match catch_unwind(AssertUnwindSafe(|| from_hash_writer_impl(writer))) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("FATAL: {}", panic_to_string(e));
            std::process::abort();
        }
    }
}

fn from_size_computer(sc: Pin<&mut ffi::CSizeComputer>) -> Box<CppStream<'_>> {
    match catch_unwind(AssertUnwindSafe(|| from_size_computer_impl(sc))) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("FATAL: {}", panic_to_string(e));
            std::process::abort();
        }
    }
}

// ---------------------------------------------------------------------------
// Consensus
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn network(
    net: &str,
    overwinter: i32,
    sapling: i32,
    blossom: i32,
    heartwood: i32,
    canopy: i32,
    nu5: i32,
    nu6: i32,
    nu6_1: i32,
) -> Result<Box<Network>, String> {
    catch_unwind(AssertUnwindSafe(|| {
        network_impl(net, overwinter, sapling, blossom, heartwood, canopy, nu5, nu6, nu6_1)
            .map_err(|e| e.to_string())
    }))
    .unwrap_or_else(|e| Err(panic_to_string(e)))
}

// ---------------------------------------------------------------------------
// Bundle cache
// ---------------------------------------------------------------------------

fn bundlecache_init(cache_bytes: usize) {
    if let Err(e) = catch_unwind(AssertUnwindSafe(|| bundlecache_init_impl(cache_bytes))) {
        eprintln!("FATAL: {}", panic_to_string(e));
        std::process::abort();
    }
}

// ---------------------------------------------------------------------------
// Sapling parse / bundle / builder free functions
// ---------------------------------------------------------------------------

fn parse_v4_sapling_spend(bytes: &[u8]) -> Result<Box<Spend>, String> {
    catch_unwind(AssertUnwindSafe(|| parse_v4_sapling_spend_impl(bytes)))
        .unwrap_or_else(|e| Err(panic_to_string(e)))
}

fn parse_v4_sapling_output(bytes: &[u8]) -> Result<Box<Output>, String> {
    catch_unwind(AssertUnwindSafe(|| parse_v4_sapling_output_impl(bytes)))
        .unwrap_or_else(|e| Err(panic_to_string(e)))
}

fn none_sapling_bundle() -> Box<SaplingBundle> {
    match catch_unwind(AssertUnwindSafe(none_sapling_bundle_impl)) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("FATAL: {}", panic_to_string(e));
            std::process::abort();
        }
    }
}

fn parse_v5_sapling_bundle(stream: &mut CppStream<'_>) -> Result<Box<SaplingBundle>, String> {
    catch_unwind(AssertUnwindSafe(|| parse_v5_sapling_bundle_impl(stream)))
        .unwrap_or_else(|e| Err(panic_to_string(e)))
}

fn new_bundle_assembler() -> Box<SaplingBundleAssembler> {
    match catch_unwind(AssertUnwindSafe(new_bundle_assembler_impl)) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("FATAL: {}", panic_to_string(e));
            std::process::abort();
        }
    }
}

fn parse_v4_sapling_components(
    stream: &mut CppStream<'_>,
    has_sapling: bool,
) -> Result<Box<SaplingBundleAssembler>, String> {
    catch_unwind(AssertUnwindSafe(|| {
        parse_v4_sapling_components_impl(stream, has_sapling)
    }))
    .unwrap_or_else(|e| Err(panic_to_string(e)))
}

fn finish_bundle_assembly(
    assembler: Box<SaplingBundleAssembler>,
    binding_sig: [u8; 64],
) -> Box<SaplingBundle> {
    match catch_unwind(AssertUnwindSafe(|| {
        finish_bundle_assembly_impl(assembler, binding_sig)
    })) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("FATAL: {}", panic_to_string(e));
            std::process::abort();
        }
    }
}

fn new_sapling_builder(
    network: &Network,
    height: u32,
    anchor: [u8; 32],
    coinbase: bool,
) -> Result<Box<SaplingBuilder>, String> {
    catch_unwind(AssertUnwindSafe(|| {
        new_sapling_builder_impl(network, height, anchor, coinbase)
    }))
    .unwrap_or_else(|e| Err(panic_to_string(e)))
}

fn build_sapling_bundle(
    builder: Box<SaplingBuilder>,
) -> Result<Box<SaplingUnauthorizedBundle>, String> {
    catch_unwind(AssertUnwindSafe(|| build_sapling_bundle_impl(builder)))
        .unwrap_or_else(|e| Err(panic_to_string(e)))
}

fn apply_sapling_bundle_signatures(
    bundle: Box<SaplingUnauthorizedBundle>,
    sighash_bytes: [u8; 32],
) -> Result<Box<SaplingBundle>, String> {
    catch_unwind(AssertUnwindSafe(|| {
        apply_sapling_bundle_signatures_impl(bundle, sighash_bytes)
    }))
    .unwrap_or_else(|e| Err(panic_to_string(e)))
}

fn init_verifier() -> Box<Verifier> {
    match catch_unwind(AssertUnwindSafe(init_verifier_impl)) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("FATAL: {}", panic_to_string(e));
            std::process::abort();
        }
    }
}

fn init_sapling_batch_validator(cache_store: bool) -> Box<SaplingBatchValidator> {
    match catch_unwind(AssertUnwindSafe(|| init_sapling_batch_validator_impl(cache_store))) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("FATAL: {}", panic_to_string(e));
            std::process::abort();
        }
    }
}

// ---------------------------------------------------------------------------
// ZIP 32 Key Derivation
// ---------------------------------------------------------------------------

fn xsk_master(seed: &[u8]) -> Result<[u8; 169], String> {
    catch_unwind(AssertUnwindSafe(|| xsk_master_impl(seed)))
        .unwrap_or_else(|e| Err(panic_to_string(e)))
}

fn xsk_derive(xsk_parent: &[u8; 169], i: u32) -> Result<[u8; 169], String> {
    catch_unwind(AssertUnwindSafe(|| xsk_derive_impl(xsk_parent, i)))
        .unwrap_or_else(|e| Err(panic_to_string(e)))
}

fn xsk_derive_internal(xsk_external: &[u8; 169]) -> Result<[u8; 169], String> {
    catch_unwind(AssertUnwindSafe(|| xsk_derive_internal_impl(xsk_external)))
        .unwrap_or_else(|e| Err(panic_to_string(e)))
}

fn xsk_to_fvk(xsk: &[u8; 169]) -> Result<[u8; 96], String> {
    catch_unwind(AssertUnwindSafe(|| xsk_to_fvk_impl(xsk)))
        .unwrap_or_else(|e| Err(panic_to_string(e)))
}

fn xsk_to_dk(xsk: &[u8; 169]) -> Result<[u8; 32], String> {
    catch_unwind(AssertUnwindSafe(|| xsk_to_dk_impl(xsk)))
        .unwrap_or_else(|e| Err(panic_to_string(e)))
}

fn xsk_to_ivk(xsk: &[u8; 169]) -> Result<[u8; 32], String> {
    catch_unwind(AssertUnwindSafe(|| xsk_to_ivk_impl(xsk)))
        .unwrap_or_else(|e| Err(panic_to_string(e)))
}

fn xsk_to_default_address(xsk: &[u8; 169]) -> Result<[u8; 43], String> {
    catch_unwind(AssertUnwindSafe(|| xsk_to_default_address_impl(xsk)))
        .unwrap_or_else(|e| Err(panic_to_string(e)))
}

fn derive_internal_fvk(fvk: &[u8; 96], dk: [u8; 32]) -> Result<ffi::Zip32Fvk, String> {
    catch_unwind(AssertUnwindSafe(|| derive_internal_fvk_impl(fvk, dk)))
        .unwrap_or_else(|e| Err(panic_to_string(e)))
}

fn zip32_address(fvk: &[u8; 96], dk: [u8; 32], j: [u8; 11]) -> Result<[u8; 43], String> {
    catch_unwind(AssertUnwindSafe(|| zip32_address_impl(fvk, dk, j)))
        .unwrap_or_else(|e| Err(panic_to_string(e)))
}

fn zip32_find_address(
    fvk: &[u8; 96],
    dk: [u8; 32],
    j: [u8; 11],
) -> Result<ffi::Zip32Address, String> {
    catch_unwind(AssertUnwindSafe(|| zip32_find_address_impl(fvk, dk, j)))
        .unwrap_or_else(|e| Err(panic_to_string(e)))
}

fn diversifier_index(dk: [u8; 32], d: [u8; 11]) -> [u8; 11] {
    match catch_unwind(AssertUnwindSafe(|| diversifier_index_impl(dk, d))) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ERROR: {} — returning zeroed index", panic_to_string(e));
            [0u8; 11]
        }
    }
}

fn fvk_to_ivk(fvk: &[u8; 96]) -> Result<[u8; 32], String> {
    catch_unwind(AssertUnwindSafe(|| fvk_to_ivk_impl(fvk)))
        .unwrap_or_else(|e| Err(panic_to_string(e)))
}

fn fvk_default_address(fvk: &[u8; 96], dk: [u8; 32]) -> Result<[u8; 43], String> {
    catch_unwind(AssertUnwindSafe(|| fvk_default_address_impl(fvk, dk)))
        .unwrap_or_else(|e| Err(panic_to_string(e)))
}

// ---------------------------------------------------------------------------
// Wallet / Note Decryption
// ---------------------------------------------------------------------------

fn try_sapling_note_decryption(
    network: &Network,
    height: u32,
    raw_ivk: &[u8; 32],
    output: ffi::SaplingShieldedOutput,
) -> Result<Box<DecryptedSaplingOutput>, String> {
    catch_unwind(AssertUnwindSafe(|| {
        try_sapling_note_decryption_impl(network, height, raw_ivk, output)
            .map_err(|e| e.to_string())
    }))
    .unwrap_or_else(|e| Err(panic_to_string(e)))
}

fn try_sapling_output_recovery(
    network: &Network,
    height: u32,
    ovk: [u8; 32],
    output: ffi::SaplingShieldedOutput,
) -> Result<Box<DecryptedSaplingOutput>, String> {
    catch_unwind(AssertUnwindSafe(|| {
        try_sapling_output_recovery_impl(network, height, ovk, output)
            .map_err(|e| e.to_string())
    }))
    .unwrap_or_else(|e| Err(panic_to_string(e)))
}

// ---------------------------------------------------------------------------
// Incremental Merkle Tree
// ---------------------------------------------------------------------------

fn new_sapling_frontier() -> Box<SaplingFrontier> {
    match catch_unwind(AssertUnwindSafe(new_sapling_frontier_impl)) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("FATAL: {}", panic_to_string(e));
            std::process::abort();
        }
    }
}

fn frontier_append(tree: &mut SaplingFrontier, cmu: &[u8; 32]) -> Result<(), String> {
    catch_unwind(AssertUnwindSafe(|| frontier_append_impl(tree, cmu)))
        .unwrap_or_else(|e| Err(panic_to_string(e)))
}

fn frontier_root(tree: &SaplingFrontier) -> [u8; 32] {
    match catch_unwind(AssertUnwindSafe(|| frontier_root_impl(tree))) {
        Ok(v) => v,
        Err(e) => {
            // #401: A zeroed root would cause silent consensus divergence.
            // Abort immediately so the problem is visible and cannot corrupt state.
            eprintln!("FATAL: {} — aborting to prevent consensus divergence", panic_to_string(e));
            std::process::abort();
        }
    }
}

fn frontier_size(tree: &SaplingFrontier) -> u64 {
    match catch_unwind(AssertUnwindSafe(|| frontier_size_impl(tree))) {
        Ok(v) => v,
        Err(e) => {
            // #401: Returning 0 on panic would silently corrupt tree state tracking.
            // Abort immediately so the problem is visible.
            eprintln!("FATAL: {} — aborting to prevent consensus divergence", panic_to_string(e));
            std::process::abort();
        }
    }
}

fn frontier_serialize(tree: &SaplingFrontier) -> Vec<u8> {
    match catch_unwind(AssertUnwindSafe(|| frontier_serialize_impl(tree))) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("FATAL: frontier_serialize panic: {} — aborting to prevent consensus divergence (#605)", panic_to_string(e));
            std::process::abort();
        }
    }
}

fn frontier_deserialize(data: &[u8]) -> Result<Box<SaplingFrontier>, String> {
    catch_unwind(AssertUnwindSafe(|| frontier_deserialize_impl(data)))
        .unwrap_or_else(|e| Err(panic_to_string(e)))
}

fn witness_from_frontier(tree: &SaplingFrontier) -> Result<Box<SaplingWitness>, String> {
    catch_unwind(AssertUnwindSafe(|| witness_from_frontier_impl(tree)))
        .unwrap_or_else(|e| Err(panic_to_string(e)))
}

fn witness_append(wit: &mut SaplingWitness, cmu: &[u8; 32]) -> Result<(), String> {
    catch_unwind(AssertUnwindSafe(|| witness_append_impl(wit, cmu)))
        .unwrap_or_else(|e| Err(panic_to_string(e)))
}

fn witness_root(wit: &SaplingWitness) -> [u8; 32] {
    match catch_unwind(AssertUnwindSafe(|| witness_root_impl(wit))) {
        Ok(v) => v,
        Err(e) => {
            // #401: A zeroed witness root would cause silent consensus divergence.
            // Abort immediately so the problem is visible and cannot corrupt state.
            eprintln!("FATAL: {} — aborting to prevent consensus divergence", panic_to_string(e));
            std::process::abort();
        }
    }
}

fn witness_position(wit: &SaplingWitness) -> u64 {
    match catch_unwind(AssertUnwindSafe(|| witness_position_impl(wit))) {
        Ok(v) => v,
        Err(e) => {
            // #401: Returning 0 on panic would silently corrupt witness position tracking.
            // Abort immediately so the problem is visible.
            eprintln!("FATAL: {} — aborting to prevent consensus divergence", panic_to_string(e));
            std::process::abort();
        }
    }
}

fn witness_path(wit: &SaplingWitness) -> Result<[u8; 1065], String> {
    catch_unwind(AssertUnwindSafe(|| witness_path_impl(wit)))
        .unwrap_or_else(|e| Err(panic_to_string(e)))
}

fn witness_serialize(wit: &SaplingWitness) -> Vec<u8> {
    match catch_unwind(AssertUnwindSafe(|| witness_serialize_impl(wit))) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("FATAL: witness_serialize panic: {} — aborting to prevent silent data loss", panic_to_string(e));
            std::process::abort();
        }
    }
}

fn witness_deserialize(data: &[u8]) -> Result<Box<SaplingWitness>, String> {
    catch_unwind(AssertUnwindSafe(|| witness_deserialize_impl(data)))
        .unwrap_or_else(|e| Err(panic_to_string(e)))
}

// ---------------------------------------------------------------------------
// Parameter Initialization
// ---------------------------------------------------------------------------

fn init_sapling_params(spend_path: &str, output_path: &str) -> Result<(), String> {
    catch_unwind(AssertUnwindSafe(|| {
        init_sapling_params_impl(spend_path, output_path)
    }))
    .unwrap_or_else(|e| Err(panic_to_string(e)))
}

fn is_sapling_initialized() -> bool {
    match catch_unwind(AssertUnwindSafe(is_sapling_initialized_impl)) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ERROR: {} — returning false", panic_to_string(e));
            false
        }
    }
}

// ---------------------------------------------------------------------------
// HMP Groth16 Participation Proofs
// ---------------------------------------------------------------------------

fn init_hmp_params() -> Result<(), String> {
    catch_unwind(AssertUnwindSafe(init_hmp_params_impl))
        .unwrap_or_else(|e| Err(panic_to_string(e)))
}

fn is_hmp_initialized() -> bool {
    match catch_unwind(AssertUnwindSafe(is_hmp_initialized_impl)) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("ERROR: {} — returning false", panic_to_string(e));
            false
        }
    }
}

fn hmp_create_proof(
    sk_bytes: &[u8; 32],
    block_hash: &[u8; 32],
    chain_state_hash: &[u8; 32],
) -> Result<Vec<u8>, String> {
    catch_unwind(AssertUnwindSafe(|| {
        hmp_create_proof_impl(sk_bytes, block_hash, chain_state_hash)
    }))
    .unwrap_or_else(|e| Err(panic_to_string(e)))
}

fn hmp_verify_proof(
    proof_bytes: &[u8],
    block_hash: &[u8; 32],
    commitment: &[u8; 32],
) -> Result<bool, String> {
    catch_unwind(AssertUnwindSafe(|| {
        hmp_verify_proof_impl(proof_bytes, block_hash, commitment)
    }))
    .unwrap_or_else(|e| Err(panic_to_string(e)))
}

fn hmp_compute_commitment(
    sk_bytes: &[u8; 32],
    block_hash: &[u8; 32],
    chain_state_hash: &[u8; 32],
) -> Result<[u8; 32], String> {
    catch_unwind(AssertUnwindSafe(|| {
        hmp_compute_commitment_impl(sk_bytes, block_hash, chain_state_hash)
    }))
    .unwrap_or_else(|e| Err(panic_to_string(e)))
}

// ===========================================================================
// CXX Bridge declaration — unchanged interface, but CXX now calls our
// catch_unwind wrappers above instead of the raw implementation functions.
// ===========================================================================

#[allow(clippy::needless_lifetimes)]
#[cxx::bridge]
pub(crate) mod ffi {
    extern "C++" {
        include!("hash.h");
        include!("streams.h");

        #[cxx_name = "RustDataStream"]
        type RustStream = crate::streams::ffi::RustStream;
        type CAutoFile = crate::streams::ffi::CAutoFile;
        type CBufferedFile = crate::streams::ffi::CBufferedFile;
        type CHashWriter = crate::streams::ffi::CHashWriter;
        type CSizeComputer = crate::streams::ffi::CSizeComputer;
    }
    #[namespace = "stream"]
    extern "Rust" {
        type CppStream<'a>;

        fn from_data(stream: Pin<&mut RustStream>) -> Box<CppStream<'_>>;
        fn from_auto_file(file: Pin<&mut CAutoFile>) -> Box<CppStream<'_>>;
        fn from_buffered_file(file: Pin<&mut CBufferedFile>) -> Box<CppStream<'_>>;
        fn from_hash_writer(writer: Pin<&mut CHashWriter>) -> Box<CppStream<'_>>;
        fn from_size_computer(sc: Pin<&mut CSizeComputer>) -> Box<CppStream<'_>>;
    }

    #[namespace = "consensus"]
    extern "Rust" {
        type Network;

        #[allow(clippy::too_many_arguments)]
        fn network(
            network: &str,
            overwinter: i32,
            sapling: i32,
            blossom: i32,
            heartwood: i32,
            canopy: i32,
            nu5: i32,
            nu6: i32,
            nu6_1: i32,
        ) -> Result<Box<Network>>;
    }

    #[namespace = "libkerrigan"]
    unsafe extern "C++" {
        include!("sapling/cache.h");

        type BundleValidityCache;

        fn NewBundleValidityCache(kind: &str, bytes: usize) -> UniquePtr<BundleValidityCache>;
        fn insert(self: Pin<&mut BundleValidityCache>, entry: [u8; 32]);
        fn contains(&self, entry: &[u8; 32], erase: bool) -> bool;
    }
    #[namespace = "bundlecache"]
    extern "Rust" {
        #[rust_name = "bundlecache_init"]
        fn init(cache_bytes: usize);
    }

    // ----- Sapling ------------------------------------------------

    #[namespace = "sapling"]
    extern "Rust" {
        type Spend;

        #[cxx_name = "parse_v4_spend"]
        fn parse_v4_sapling_spend(bytes: &[u8]) -> Result<Box<Spend>>;
        fn cv(self: &Spend) -> [u8; 32];
        fn anchor(self: &Spend) -> [u8; 32];
        fn nullifier(self: &Spend) -> [u8; 32];
        fn rk(self: &Spend) -> [u8; 32];
        fn zkproof(self: &Spend) -> [u8; 192];
        fn spend_auth_sig(self: &Spend) -> [u8; 64];

        type Output;

        #[cxx_name = "parse_v4_output"]
        fn parse_v4_sapling_output(bytes: &[u8]) -> Result<Box<Output>>;
        fn cv(self: &Output) -> [u8; 32];
        fn cmu(self: &Output) -> [u8; 32];
        fn ephemeral_key(self: &Output) -> [u8; 32];
        fn enc_ciphertext(self: &Output) -> [u8; 580];
        fn out_ciphertext(self: &Output) -> [u8; 80];
        fn zkproof(self: &Output) -> [u8; 192];
        fn serialize_v4(self: &Output, stream: &mut CppStream<'_>) -> Result<()>;

        #[cxx_name = "Bundle"]
        type SaplingBundle;

        #[cxx_name = "none_bundle"]
        fn none_sapling_bundle() -> Box<SaplingBundle>;
        fn box_clone(self: &SaplingBundle) -> Box<SaplingBundle>;
        #[cxx_name = "parse_v5_bundle"]
        fn parse_v5_sapling_bundle(stream: &mut CppStream<'_>) -> Result<Box<SaplingBundle>>;
        fn serialize_v4_components(
            self: &SaplingBundle,
            stream: &mut CppStream<'_>,
            has_sapling: bool,
        ) -> Result<()>;
        fn serialize_v5(self: &SaplingBundle, stream: &mut CppStream<'_>) -> Result<()>;
        fn recursive_dynamic_usage(self: &SaplingBundle) -> usize;
        fn is_present(self: &SaplingBundle) -> bool;
        fn spends(self: &SaplingBundle) -> Vec<Spend>;
        fn outputs(self: &SaplingBundle) -> Vec<Output>;
        fn num_spends(self: &SaplingBundle) -> usize;
        fn num_outputs(self: &SaplingBundle) -> usize;
        fn value_balance_zat(self: &SaplingBundle) -> i64;
        fn binding_sig(self: &SaplingBundle) -> Result<[u8; 64]>;

        #[rust_name = "SaplingBundleAssembler"]
        type BundleAssembler;

        fn new_bundle_assembler() -> Box<SaplingBundleAssembler>;
        #[cxx_name = "parse_v4_components"]
        fn parse_v4_sapling_components(
            stream: &mut CppStream<'_>,
            has_sapling: bool,
        ) -> Result<Box<SaplingBundleAssembler>>;
        fn have_actions(self: &SaplingBundleAssembler) -> bool;
        fn finish_bundle_assembly(
            assembler: Box<SaplingBundleAssembler>,
            binding_sig: [u8; 64],
        ) -> Box<SaplingBundle>;

        #[cxx_name = "Builder"]
        type SaplingBuilder;

        #[cxx_name = "new_builder"]
        fn new_sapling_builder(
            network: &Network,
            height: u32,
            anchor: [u8; 32],
            coinbase: bool,
        ) -> Result<Box<SaplingBuilder>>;
        fn add_spend(
            self: &mut SaplingBuilder,
            extsk: &[u8],
            recipient: [u8; 43],
            value: u64,
            rcm: [u8; 32],
            merkle_path: [u8; 1065],
        ) -> Result<()>;
        fn add_recipient(
            self: &mut SaplingBuilder,
            ovk: [u8; 32],
            to: [u8; 43],
            value: u64,
            memo: [u8; 512],
        ) -> Result<()>;
        fn add_recipient_no_ovk(
            self: &mut SaplingBuilder,
            to: [u8; 43],
            value: u64,
            memo: [u8; 512],
        ) -> Result<()>;
        #[cxx_name = "build_bundle"]
        fn build_sapling_bundle(
            builder: Box<SaplingBuilder>,
        ) -> Result<Box<SaplingUnauthorizedBundle>>;

        #[cxx_name = "UnauthorizedBundle"]
        type SaplingUnauthorizedBundle;

        fn num_spends(self: &SaplingUnauthorizedBundle) -> usize;
        fn num_outputs(self: &SaplingUnauthorizedBundle) -> usize;
        fn value_balance_zat(self: &SaplingUnauthorizedBundle) -> i64;

        fn spend_cv(self: &SaplingUnauthorizedBundle, i: usize) -> Result<[u8; 32]>;
        fn spend_anchor(self: &SaplingUnauthorizedBundle, i: usize) -> Result<[u8; 32]>;
        fn spend_nullifier(self: &SaplingUnauthorizedBundle, i: usize) -> Result<[u8; 32]>;
        fn spend_rk(self: &SaplingUnauthorizedBundle, i: usize) -> Result<[u8; 32]>;
        fn spend_zkproof(self: &SaplingUnauthorizedBundle, i: usize) -> Result<[u8; 192]>;

        fn output_cv(self: &SaplingUnauthorizedBundle, i: usize) -> Result<[u8; 32]>;
        fn output_cmu(self: &SaplingUnauthorizedBundle, i: usize) -> Result<[u8; 32]>;
        fn output_ephemeral_key(self: &SaplingUnauthorizedBundle, i: usize) -> Result<[u8; 32]>;
        fn output_enc_ciphertext(self: &SaplingUnauthorizedBundle, i: usize) -> Result<[u8; 580]>;
        fn output_out_ciphertext(self: &SaplingUnauthorizedBundle, i: usize) -> Result<[u8; 80]>;
        fn output_zkproof(self: &SaplingUnauthorizedBundle, i: usize) -> Result<[u8; 192]>;

        #[cxx_name = "apply_bundle_signatures"]
        fn apply_sapling_bundle_signatures(
            bundle: Box<SaplingUnauthorizedBundle>,
            sighash_bytes: [u8; 32],
        ) -> Result<Box<SaplingBundle>>;

        type Verifier;

        fn init_verifier() -> Box<Verifier>;
        #[allow(clippy::too_many_arguments)]
        fn check_spend(
            self: &mut Verifier,
            cv: &[u8; 32],
            anchor: &[u8; 32],
            nullifier: &[u8; 32],
            rk: &[u8; 32],
            zkproof: &[u8; 192],
            spend_auth_sig: &[u8; 64],
            sighash_value: &[u8; 32],
        ) -> bool;
        fn check_output(
            self: &mut Verifier,
            cv: &[u8; 32],
            cm: &[u8; 32],
            ephemeral_key: &[u8; 32],
            zkproof: &[u8; 192],
        ) -> bool;
        fn final_check(
            self: &Verifier,
            value_balance: i64,
            binding_sig: &[u8; 64],
            sighash_value: &[u8; 32],
        ) -> bool;

        #[cxx_name = "BatchValidator"]
        type SaplingBatchValidator;
        #[cxx_name = "init_batch_validator"]
        fn init_sapling_batch_validator(cache_store: bool) -> Box<SaplingBatchValidator>;
        fn check_bundle(
            self: &mut SaplingBatchValidator,
            bundle: Box<SaplingBundle>,
            sighash: [u8; 32],
        ) -> bool;
        fn validate(self: &mut SaplingBatchValidator) -> bool;
    }

    // ----- ZIP 32 Key Derivation -----------------------------------

    #[namespace = "sapling::zip32"]
    struct Zip32Fvk {
        fvk: [u8; 96],
        dk: [u8; 32],
    }

    #[namespace = "sapling::zip32"]
    struct Zip32Address {
        j: [u8; 11],
        addr: [u8; 43],
    }

    #[namespace = "sapling::zip32"]
    extern "Rust" {
        /// Derive master ExtendedSpendingKey from seed bytes.
        fn xsk_master(seed: &[u8]) -> Result<[u8; 169]>;

        /// Derive child ExtendedSpendingKey from parent.
        fn xsk_derive(xsk_parent: &[u8; 169], i: u32) -> Result<[u8; 169]>;

        /// Derive the internal (change) ExtSK from an external ExtSK.
        fn xsk_derive_internal(xsk_external: &[u8; 169]) -> Result<[u8; 169]>;

        /// Extract the 96-byte FullViewingKey (ak || nk || ovk) from an ExtSK.
        fn xsk_to_fvk(xsk: &[u8; 169]) -> Result<[u8; 96]>;

        /// Extract the 32-byte DiversifierKey from an ExtSK.
        fn xsk_to_dk(xsk: &[u8; 169]) -> Result<[u8; 32]>;

        /// Extract the 32-byte IncomingViewingKey from an ExtSK.
        fn xsk_to_ivk(xsk: &[u8; 169]) -> Result<[u8; 32]>;

        /// Derive the default payment address (43 bytes) from an ExtSK.
        fn xsk_to_default_address(xsk: &[u8; 169]) -> Result<[u8; 43]>;

        /// Derive the internal FVK + DK from a FVK + DK.
        fn derive_internal_fvk(fvk: &[u8; 96], dk: [u8; 32]) -> Result<Zip32Fvk>;

        /// Derive a payment address at diversifier index j.
        #[cxx_name = "address"]
        fn zip32_address(fvk: &[u8; 96], dk: [u8; 32], j: [u8; 11]) -> Result<[u8; 43]>;

        /// Find the next valid diversified address at or above index j.
        #[cxx_name = "find_address"]
        fn zip32_find_address(fvk: &[u8; 96], dk: [u8; 32], j: [u8; 11]) -> Result<Zip32Address>;

        /// Get the diversifier index for a given diversifier.
        fn diversifier_index(dk: [u8; 32], d: [u8; 11]) -> [u8; 11];

        /// Derive IVK from a 96-byte FVK.
        fn fvk_to_ivk(fvk: &[u8; 96]) -> Result<[u8; 32]>;

        /// Derive the default payment address from a FVK + DK.
        fn fvk_default_address(fvk: &[u8; 96], dk: [u8; 32]) -> Result<[u8; 43]>;
    }

    // ----- Wallet / Note Decryption ---------------------------------

    #[namespace = "wallet"]
    struct SaplingShieldedOutput {
        cv: [u8; 32],
        cmu: [u8; 32],
        ephemeral_key: [u8; 32],
        enc_ciphertext: [u8; 580],
        out_ciphertext: [u8; 80],
    }

    #[namespace = "wallet"]
    extern "Rust" {
        fn try_sapling_note_decryption(
            network: &Network,
            height: u32,
            raw_ivk: &[u8; 32],
            output: SaplingShieldedOutput,
        ) -> Result<Box<DecryptedSaplingOutput>>;
        fn try_sapling_output_recovery(
            network: &Network,
            height: u32,
            ovk: [u8; 32],
            output: SaplingShieldedOutput,
        ) -> Result<Box<DecryptedSaplingOutput>>;

        type DecryptedSaplingOutput;
        fn note_value(self: &DecryptedSaplingOutput) -> u64;
        fn note_rseed(self: &DecryptedSaplingOutput) -> [u8; 32];
        fn zip_212_enabled(self: &DecryptedSaplingOutput) -> bool;
        fn recipient_d(self: &DecryptedSaplingOutput) -> [u8; 11];
        fn recipient_pk_d(self: &DecryptedSaplingOutput) -> [u8; 32];
        fn memo(self: &DecryptedSaplingOutput) -> [u8; 512];
    }

    // ----- Incremental Merkle Tree ----------------------------------

    #[namespace = "sapling::tree"]
    extern "Rust" {
        // -- Frontier (consensus) --

        type SaplingFrontier;

        /// Create a new empty commitment tree frontier.
        fn new_sapling_frontier() -> Box<SaplingFrontier>;

        /// Append a note commitment to the frontier.
        fn frontier_append(tree: &mut SaplingFrontier, cmu: &[u8; 32]) -> Result<()>;

        /// Get the Merkle root hash of the frontier.
        fn frontier_root(tree: &SaplingFrontier) -> [u8; 32];

        /// Number of leaves in the tree.
        fn frontier_size(tree: &SaplingFrontier) -> u64;

        /// Serialize the frontier for LevelDB storage.
        fn frontier_serialize(tree: &SaplingFrontier) -> Vec<u8>;

        /// Deserialize a frontier from bytes.
        fn frontier_deserialize(data: &[u8]) -> Result<Box<SaplingFrontier>>;

        // -- Witness (wallet) --

        type SaplingWitness;

        /// Create a witness for the most recently appended leaf.
        fn witness_from_frontier(tree: &SaplingFrontier) -> Result<Box<SaplingWitness>>;

        /// Update the witness with a new commitment.
        fn witness_append(wit: &mut SaplingWitness, cmu: &[u8; 32]) -> Result<()>;

        /// Get the Merkle root from the witness.
        fn witness_root(wit: &SaplingWitness) -> [u8; 32];

        /// Get the position of the witnessed leaf.
        fn witness_position(wit: &SaplingWitness) -> u64;

        /// Get the 1065-byte Merkle path for the Sapling prover.
        fn witness_path(wit: &SaplingWitness) -> Result<[u8; 1065]>;

        /// Serialize the witness for wallet storage.
        fn witness_serialize(wit: &SaplingWitness) -> Vec<u8>;

        /// Deserialize a witness from bytes.
        fn witness_deserialize(data: &[u8]) -> Result<Box<SaplingWitness>>;
    }

    // ----- Parameter Initialization ---------------------------------

    #[namespace = "sapling"]
    extern "Rust" {
        /// Load Sapling zk-SNARK parameters from disk.
        /// Verifies file integrity (size + BLAKE2b hash) before use.
        fn init_sapling_params(spend_path: &str, output_path: &str) -> Result<()>;

        /// Returns true if Sapling parameters have been loaded.
        fn is_sapling_initialized() -> bool;
    }

    // ----- HMP Groth16 Participation Proofs --------------------------

    #[namespace = "hmp"]
    extern "Rust" {
        /// Initialize HMP Groth16 parameters (trusted setup).
        /// Generates parameters for the MiMC commitment circuit.
        fn init_hmp_params() -> Result<()>;

        /// Returns true if HMP parameters have been initialized.
        fn is_hmp_initialized() -> bool;

        /// Create a Groth16 participation proof (192 bytes).
        fn hmp_create_proof(
            sk_bytes: &[u8; 32],
            block_hash: &[u8; 32],
            chain_state_hash: &[u8; 32],
        ) -> Result<Vec<u8>>;

        /// Verify a Groth16 participation proof.
        fn hmp_verify_proof(
            proof_bytes: &[u8],
            block_hash: &[u8; 32],
            commitment: &[u8; 32],
        ) -> Result<bool>;

        /// Compute commitment for given inputs (used by prover and verifier).
        fn hmp_compute_commitment(
            sk_bytes: &[u8; 32],
            block_hash: &[u8; 32],
            chain_state_hash: &[u8; 32],
        ) -> Result<[u8; 32]>;
    }
}
