#pragma once
#include "hash.h"
#include "streams.h"
#include "sapling/cache.h"
#include "rust/cxx.h"
#include <memory>

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdollar-in-identifier-extension"
#endif // __clang__

namespace stream {
  struct CppStream;
}
namespace consensus {
  struct Network;
}
namespace libkerrigan {
  using BundleValidityCache = ::libkerrigan::BundleValidityCache;
}
namespace sapling {
  struct Spend;
  struct Output;
  struct Bundle;
  struct BundleAssembler;
  struct Builder;
  struct UnauthorizedBundle;
  struct Verifier;
  struct BatchValidator;
  namespace zip32 {
    struct Zip32Fvk;
    struct Zip32Address;
  }
  namespace tree {
    struct SaplingFrontier;
    struct SaplingWitness;
  }
}
namespace wallet {
  struct SaplingShieldedOutput;
  struct DecryptedSaplingOutput;
}

namespace stream {
#ifndef CXXBRIDGE1_STRUCT_stream$CppStream
#define CXXBRIDGE1_STRUCT_stream$CppStream
struct CppStream final : public ::rust::Opaque {
  ~CppStream() = delete;

private:
  friend ::rust::layout;
  struct layout {
    static ::std::size_t size() noexcept;
    static ::std::size_t align() noexcept;
  };
};
#endif // CXXBRIDGE1_STRUCT_stream$CppStream
} // namespace stream

namespace consensus {
#ifndef CXXBRIDGE1_STRUCT_consensus$Network
#define CXXBRIDGE1_STRUCT_consensus$Network
struct Network final : public ::rust::Opaque {
  ~Network() = delete;

private:
  friend ::rust::layout;
  struct layout {
    static ::std::size_t size() noexcept;
    static ::std::size_t align() noexcept;
  };
};
#endif // CXXBRIDGE1_STRUCT_consensus$Network
} // namespace consensus

namespace sapling {
#ifndef CXXBRIDGE1_STRUCT_sapling$Spend
#define CXXBRIDGE1_STRUCT_sapling$Spend
struct Spend final : public ::rust::Opaque {
  ::std::array<::std::uint8_t, 32> cv() const noexcept;
  ::std::array<::std::uint8_t, 32> anchor() const noexcept;
  ::std::array<::std::uint8_t, 32> nullifier() const noexcept;
  ::std::array<::std::uint8_t, 32> rk() const noexcept;
  ::std::array<::std::uint8_t, 192> zkproof() const noexcept;
  ::std::array<::std::uint8_t, 64> spend_auth_sig() const noexcept;
  ~Spend() = delete;

private:
  friend ::rust::layout;
  struct layout {
    static ::std::size_t size() noexcept;
    static ::std::size_t align() noexcept;
  };
};
#endif // CXXBRIDGE1_STRUCT_sapling$Spend

#ifndef CXXBRIDGE1_STRUCT_sapling$Output
#define CXXBRIDGE1_STRUCT_sapling$Output
struct Output final : public ::rust::Opaque {
  ::std::array<::std::uint8_t, 32> cv() const noexcept;
  ::std::array<::std::uint8_t, 32> cmu() const noexcept;
  ::std::array<::std::uint8_t, 32> ephemeral_key() const noexcept;
  ::std::array<::std::uint8_t, 580> enc_ciphertext() const noexcept;
  ::std::array<::std::uint8_t, 80> out_ciphertext() const noexcept;
  ::std::array<::std::uint8_t, 192> zkproof() const noexcept;
  void serialize_v4(::stream::CppStream &stream) const;
  ~Output() = delete;

private:
  friend ::rust::layout;
  struct layout {
    static ::std::size_t size() noexcept;
    static ::std::size_t align() noexcept;
  };
};
#endif // CXXBRIDGE1_STRUCT_sapling$Output

#ifndef CXXBRIDGE1_STRUCT_sapling$Bundle
#define CXXBRIDGE1_STRUCT_sapling$Bundle
struct Bundle final : public ::rust::Opaque {
  ::rust::Box<::sapling::Bundle> box_clone() const noexcept;
  void serialize_v4_components(::stream::CppStream &stream, bool has_sapling) const;
  void serialize_v5(::stream::CppStream &stream) const;
  ::std::size_t recursive_dynamic_usage() const noexcept;
  bool is_present() const noexcept;
  ::rust::Vec<::sapling::Spend> spends() const noexcept;
  ::rust::Vec<::sapling::Output> outputs() const noexcept;
  ::std::size_t num_spends() const noexcept;
  ::std::size_t num_outputs() const noexcept;
  ::std::int64_t value_balance_zat() const noexcept;
  ::std::array<::std::uint8_t, 64> binding_sig() const;
  ~Bundle() = delete;

private:
  friend ::rust::layout;
  struct layout {
    static ::std::size_t size() noexcept;
    static ::std::size_t align() noexcept;
  };
};
#endif // CXXBRIDGE1_STRUCT_sapling$Bundle

#ifndef CXXBRIDGE1_STRUCT_sapling$BundleAssembler
#define CXXBRIDGE1_STRUCT_sapling$BundleAssembler
struct BundleAssembler final : public ::rust::Opaque {
  bool have_actions() const noexcept;
  ~BundleAssembler() = delete;

private:
  friend ::rust::layout;
  struct layout {
    static ::std::size_t size() noexcept;
    static ::std::size_t align() noexcept;
  };
};
#endif // CXXBRIDGE1_STRUCT_sapling$BundleAssembler

#ifndef CXXBRIDGE1_STRUCT_sapling$Builder
#define CXXBRIDGE1_STRUCT_sapling$Builder
struct Builder final : public ::rust::Opaque {
  void add_spend(::rust::Slice<::std::uint8_t const> extsk, ::std::array<::std::uint8_t, 43> recipient, ::std::uint64_t value, ::std::array<::std::uint8_t, 32> rcm, ::std::array<::std::uint8_t, 1065> merkle_path);
  void add_recipient(::std::array<::std::uint8_t, 32> ovk, ::std::array<::std::uint8_t, 43> to, ::std::uint64_t value, ::std::array<::std::uint8_t, 512> memo);
  void add_recipient_no_ovk(::std::array<::std::uint8_t, 43> to, ::std::uint64_t value, ::std::array<::std::uint8_t, 512> memo);
  ~Builder() = delete;

private:
  friend ::rust::layout;
  struct layout {
    static ::std::size_t size() noexcept;
    static ::std::size_t align() noexcept;
  };
};
#endif // CXXBRIDGE1_STRUCT_sapling$Builder

#ifndef CXXBRIDGE1_STRUCT_sapling$UnauthorizedBundle
#define CXXBRIDGE1_STRUCT_sapling$UnauthorizedBundle
struct UnauthorizedBundle final : public ::rust::Opaque {
  ::std::size_t num_spends() const noexcept;
  ::std::size_t num_outputs() const noexcept;
  ::std::int64_t value_balance_zat() const noexcept;
  ::std::array<::std::uint8_t, 32> spend_cv(::std::size_t i) const;
  ::std::array<::std::uint8_t, 32> spend_anchor(::std::size_t i) const;
  ::std::array<::std::uint8_t, 32> spend_nullifier(::std::size_t i) const;
  ::std::array<::std::uint8_t, 32> spend_rk(::std::size_t i) const;
  ::std::array<::std::uint8_t, 192> spend_zkproof(::std::size_t i) const;
  ::std::array<::std::uint8_t, 32> output_cv(::std::size_t i) const;
  ::std::array<::std::uint8_t, 32> output_cmu(::std::size_t i) const;
  ::std::array<::std::uint8_t, 32> output_ephemeral_key(::std::size_t i) const;
  ::std::array<::std::uint8_t, 580> output_enc_ciphertext(::std::size_t i) const;
  ::std::array<::std::uint8_t, 80> output_out_ciphertext(::std::size_t i) const;
  ::std::array<::std::uint8_t, 192> output_zkproof(::std::size_t i) const;
  ~UnauthorizedBundle() = delete;

private:
  friend ::rust::layout;
  struct layout {
    static ::std::size_t size() noexcept;
    static ::std::size_t align() noexcept;
  };
};
#endif // CXXBRIDGE1_STRUCT_sapling$UnauthorizedBundle

#ifndef CXXBRIDGE1_STRUCT_sapling$Verifier
#define CXXBRIDGE1_STRUCT_sapling$Verifier
struct Verifier final : public ::rust::Opaque {
  bool check_spend(::std::array<::std::uint8_t, 32> const &cv, ::std::array<::std::uint8_t, 32> const &anchor, ::std::array<::std::uint8_t, 32> const &nullifier, ::std::array<::std::uint8_t, 32> const &rk, ::std::array<::std::uint8_t, 192> const &zkproof, ::std::array<::std::uint8_t, 64> const &spend_auth_sig, ::std::array<::std::uint8_t, 32> const &sighash_value) noexcept;
  bool check_output(::std::array<::std::uint8_t, 32> const &cv, ::std::array<::std::uint8_t, 32> const &cm, ::std::array<::std::uint8_t, 32> const &ephemeral_key, ::std::array<::std::uint8_t, 192> const &zkproof) noexcept;
  bool final_check(::std::int64_t value_balance, ::std::array<::std::uint8_t, 64> const &binding_sig, ::std::array<::std::uint8_t, 32> const &sighash_value) const noexcept;
  ~Verifier() = delete;

private:
  friend ::rust::layout;
  struct layout {
    static ::std::size_t size() noexcept;
    static ::std::size_t align() noexcept;
  };
};
#endif // CXXBRIDGE1_STRUCT_sapling$Verifier

#ifndef CXXBRIDGE1_STRUCT_sapling$BatchValidator
#define CXXBRIDGE1_STRUCT_sapling$BatchValidator
struct BatchValidator final : public ::rust::Opaque {
  bool check_bundle(::rust::Box<::sapling::Bundle> bundle, ::std::array<::std::uint8_t, 32> sighash) noexcept;
  bool validate() noexcept;
  ~BatchValidator() = delete;

private:
  friend ::rust::layout;
  struct layout {
    static ::std::size_t size() noexcept;
    static ::std::size_t align() noexcept;
  };
};
#endif // CXXBRIDGE1_STRUCT_sapling$BatchValidator

namespace zip32 {
#ifndef CXXBRIDGE1_STRUCT_sapling$zip32$Zip32Fvk
#define CXXBRIDGE1_STRUCT_sapling$zip32$Zip32Fvk
struct Zip32Fvk final {
  ::std::array<::std::uint8_t, 96> fvk;
  ::std::array<::std::uint8_t, 32> dk;

  using IsRelocatable = ::std::true_type;
};
#endif // CXXBRIDGE1_STRUCT_sapling$zip32$Zip32Fvk

#ifndef CXXBRIDGE1_STRUCT_sapling$zip32$Zip32Address
#define CXXBRIDGE1_STRUCT_sapling$zip32$Zip32Address
struct Zip32Address final {
  ::std::array<::std::uint8_t, 11> j;
  ::std::array<::std::uint8_t, 43> addr;

  using IsRelocatable = ::std::true_type;
};
#endif // CXXBRIDGE1_STRUCT_sapling$zip32$Zip32Address
} // namespace zip32
} // namespace sapling

namespace wallet {
#ifndef CXXBRIDGE1_STRUCT_wallet$SaplingShieldedOutput
#define CXXBRIDGE1_STRUCT_wallet$SaplingShieldedOutput
struct SaplingShieldedOutput final {
  ::std::array<::std::uint8_t, 32> cv;
  ::std::array<::std::uint8_t, 32> cmu;
  ::std::array<::std::uint8_t, 32> ephemeral_key;
  ::std::array<::std::uint8_t, 580> enc_ciphertext;
  ::std::array<::std::uint8_t, 80> out_ciphertext;

  using IsRelocatable = ::std::true_type;
};
#endif // CXXBRIDGE1_STRUCT_wallet$SaplingShieldedOutput

#ifndef CXXBRIDGE1_STRUCT_wallet$DecryptedSaplingOutput
#define CXXBRIDGE1_STRUCT_wallet$DecryptedSaplingOutput
struct DecryptedSaplingOutput final : public ::rust::Opaque {
  ::std::uint64_t note_value() const noexcept;
  ::std::array<::std::uint8_t, 32> note_rseed() const noexcept;
  bool zip_212_enabled() const noexcept;
  ::std::array<::std::uint8_t, 11> recipient_d() const noexcept;
  ::std::array<::std::uint8_t, 32> recipient_pk_d() const noexcept;
  ::std::array<::std::uint8_t, 512> memo() const noexcept;
  ~DecryptedSaplingOutput() = delete;

private:
  friend ::rust::layout;
  struct layout {
    static ::std::size_t size() noexcept;
    static ::std::size_t align() noexcept;
  };
};
#endif // CXXBRIDGE1_STRUCT_wallet$DecryptedSaplingOutput
} // namespace wallet

namespace sapling {
namespace tree {
#ifndef CXXBRIDGE1_STRUCT_sapling$tree$SaplingFrontier
#define CXXBRIDGE1_STRUCT_sapling$tree$SaplingFrontier
struct SaplingFrontier final : public ::rust::Opaque {
  ~SaplingFrontier() = delete;

private:
  friend ::rust::layout;
  struct layout {
    static ::std::size_t size() noexcept;
    static ::std::size_t align() noexcept;
  };
};
#endif // CXXBRIDGE1_STRUCT_sapling$tree$SaplingFrontier

#ifndef CXXBRIDGE1_STRUCT_sapling$tree$SaplingWitness
#define CXXBRIDGE1_STRUCT_sapling$tree$SaplingWitness
struct SaplingWitness final : public ::rust::Opaque {
  ~SaplingWitness() = delete;

private:
  friend ::rust::layout;
  struct layout {
    static ::std::size_t size() noexcept;
    static ::std::size_t align() noexcept;
  };
};
#endif // CXXBRIDGE1_STRUCT_sapling$tree$SaplingWitness
} // namespace tree
} // namespace sapling

namespace stream {
::rust::Box<::stream::CppStream> from_data(::RustDataStream &stream) noexcept;

::rust::Box<::stream::CppStream> from_auto_file(::CAutoFile &file) noexcept;

::rust::Box<::stream::CppStream> from_buffered_file(::CBufferedFile &file) noexcept;

::rust::Box<::stream::CppStream> from_hash_writer(::CHashWriter &writer) noexcept;

::rust::Box<::stream::CppStream> from_size_computer(::CSizeComputer &sc) noexcept;
} // namespace stream

namespace consensus {
::rust::Box<::consensus::Network> network(::rust::Str network, ::std::int32_t overwinter, ::std::int32_t sapling, ::std::int32_t blossom, ::std::int32_t heartwood, ::std::int32_t canopy, ::std::int32_t nu5, ::std::int32_t nu6, ::std::int32_t nu6_1);
} // namespace consensus

namespace bundlecache {
void init(::std::size_t cache_bytes) noexcept;
} // namespace bundlecache

namespace sapling {
::rust::Box<::sapling::Spend> parse_v4_spend(::rust::Slice<::std::uint8_t const> bytes);

::rust::Box<::sapling::Output> parse_v4_output(::rust::Slice<::std::uint8_t const> bytes);

::rust::Box<::sapling::Bundle> none_bundle() noexcept;

::rust::Box<::sapling::Bundle> parse_v5_bundle(::stream::CppStream &stream);

::rust::Box<::sapling::BundleAssembler> new_bundle_assembler() noexcept;

::rust::Box<::sapling::BundleAssembler> parse_v4_components(::stream::CppStream &stream, bool has_sapling);

::rust::Box<::sapling::Bundle> finish_bundle_assembly(::rust::Box<::sapling::BundleAssembler> assembler, ::std::array<::std::uint8_t, 64> binding_sig) noexcept;

::rust::Box<::sapling::Builder> new_builder(::consensus::Network const &network, ::std::uint32_t height, ::std::array<::std::uint8_t, 32> anchor, bool coinbase);

::rust::Box<::sapling::UnauthorizedBundle> build_bundle(::rust::Box<::sapling::Builder> builder);

::rust::Box<::sapling::Bundle> apply_bundle_signatures(::rust::Box<::sapling::UnauthorizedBundle> bundle, ::std::array<::std::uint8_t, 32> sighash_bytes);

::rust::Box<::sapling::Verifier> init_verifier() noexcept;

::rust::Box<::sapling::BatchValidator> init_batch_validator(bool cache_store) noexcept;

namespace zip32 {
// Derive master ExtendedSpendingKey from seed bytes.
::std::array<::std::uint8_t, 169> xsk_master(::rust::Slice<::std::uint8_t const> seed);

// Derive child ExtendedSpendingKey from parent.
::std::array<::std::uint8_t, 169> xsk_derive(::std::array<::std::uint8_t, 169> const &xsk_parent, ::std::uint32_t i);

// Derive the internal (change) ExtSK from an external ExtSK.
::std::array<::std::uint8_t, 169> xsk_derive_internal(::std::array<::std::uint8_t, 169> const &xsk_external);

// Extract the 96-byte FullViewingKey (ak || nk || ovk) from an ExtSK.
::std::array<::std::uint8_t, 96> xsk_to_fvk(::std::array<::std::uint8_t, 169> const &xsk);

// Extract the 32-byte DiversifierKey from an ExtSK.
::std::array<::std::uint8_t, 32> xsk_to_dk(::std::array<::std::uint8_t, 169> const &xsk);

// Extract the 32-byte IncomingViewingKey from an ExtSK.
::std::array<::std::uint8_t, 32> xsk_to_ivk(::std::array<::std::uint8_t, 169> const &xsk);

// Derive the default payment address (43 bytes) from an ExtSK.
::std::array<::std::uint8_t, 43> xsk_to_default_address(::std::array<::std::uint8_t, 169> const &xsk);

// Derive the internal FVK + DK from a FVK + DK.
::sapling::zip32::Zip32Fvk derive_internal_fvk(::std::array<::std::uint8_t, 96> const &fvk, ::std::array<::std::uint8_t, 32> dk);

// Derive a payment address at diversifier index j.
::std::array<::std::uint8_t, 43> address(::std::array<::std::uint8_t, 96> const &fvk, ::std::array<::std::uint8_t, 32> dk, ::std::array<::std::uint8_t, 11> j);

// Find the next valid diversified address at or above index j.
::sapling::zip32::Zip32Address find_address(::std::array<::std::uint8_t, 96> const &fvk, ::std::array<::std::uint8_t, 32> dk, ::std::array<::std::uint8_t, 11> j);

// Get the diversifier index for a given diversifier.
// Returns `Err` if the underlying derivation panics (issue #1135);
// a silent zero is not a valid substitute because 0 is itself a
// legal diversifier index and would cause address collision.
::std::array<::std::uint8_t, 11> diversifier_index(::std::array<::std::uint8_t, 32> dk, ::std::array<::std::uint8_t, 11> d);

// Derive IVK from a 96-byte FVK.
::std::array<::std::uint8_t, 32> fvk_to_ivk(::std::array<::std::uint8_t, 96> const &fvk);

// Derive the default payment address from a FVK + DK.
::std::array<::std::uint8_t, 43> fvk_default_address(::std::array<::std::uint8_t, 96> const &fvk, ::std::array<::std::uint8_t, 32> dk);
} // namespace zip32
} // namespace sapling

namespace wallet {
::rust::Box<::wallet::DecryptedSaplingOutput> try_sapling_note_decryption(::consensus::Network const &network, ::std::uint32_t height, ::std::array<::std::uint8_t, 32> const &raw_ivk, ::wallet::SaplingShieldedOutput output);

::rust::Box<::wallet::DecryptedSaplingOutput> try_sapling_output_recovery(::consensus::Network const &network, ::std::uint32_t height, ::std::array<::std::uint8_t, 32> ovk, ::wallet::SaplingShieldedOutput output);
} // namespace wallet

namespace sapling {
namespace tree {
// Create a new empty commitment tree frontier.
::rust::Box<::sapling::tree::SaplingFrontier> new_sapling_frontier() noexcept;

// Append a note commitment to the frontier.
void frontier_append(::sapling::tree::SaplingFrontier &tree, ::std::array<::std::uint8_t, 32> const &cmu);

// Get the Merkle root hash of the frontier.
::std::array<::std::uint8_t, 32> frontier_root(::sapling::tree::SaplingFrontier const &tree) noexcept;

// Number of leaves in the tree.
::std::uint64_t frontier_size(::sapling::tree::SaplingFrontier const &tree) noexcept;

// Serialize the frontier for LevelDB storage.
::rust::Vec<::std::uint8_t> frontier_serialize(::sapling::tree::SaplingFrontier const &tree) noexcept;

// Deserialize a frontier from bytes.
::rust::Box<::sapling::tree::SaplingFrontier> frontier_deserialize(::rust::Slice<::std::uint8_t const> data);

// Create a witness for the most recently appended leaf.
::rust::Box<::sapling::tree::SaplingWitness> witness_from_frontier(::sapling::tree::SaplingFrontier const &tree);

// Update the witness with a new commitment.
void witness_append(::sapling::tree::SaplingWitness &wit, ::std::array<::std::uint8_t, 32> const &cmu);

// Get the Merkle root from the witness.
// Returns `Err` if computing the root panics in the underlying tree
// crate (corrupt wallet bytes); callers mark the witness stale.
::std::array<::std::uint8_t, 32> witness_root(::sapling::tree::SaplingWitness const &wit);

// Get the position of the witnessed leaf.
// Returns `Err` on panic, matching witness_root.
::std::uint64_t witness_position(::sapling::tree::SaplingWitness const &wit);

// Get the 1065-byte Merkle path for the Sapling prover.
::std::array<::std::uint8_t, 1065> witness_path(::sapling::tree::SaplingWitness const &wit);

// Serialize the witness for wallet storage.
::rust::Vec<::std::uint8_t> witness_serialize(::sapling::tree::SaplingWitness const &wit) noexcept;

// Deserialize a witness from bytes.
::rust::Box<::sapling::tree::SaplingWitness> witness_deserialize(::rust::Slice<::std::uint8_t const> data);
} // namespace tree

// Load Sapling zk-SNARK parameters from disk.
// Verifies file integrity (size + BLAKE2b hash) before use.
void init_sapling_params(::rust::Str spend_path, ::rust::Str output_path);

// Returns true if Sapling parameters have been loaded.
bool is_sapling_initialized() noexcept;
} // namespace sapling

namespace hmp {
// Initialize HMP Groth16 parameters (trusted setup).
// Generates parameters for the MiMC commitment circuit.
void init_hmp_params();

// Returns true if HMP parameters have been initialized.
bool is_hmp_initialized() noexcept;

// Create a Groth16 participation proof (192 bytes).
::rust::Vec<::std::uint8_t> hmp_create_proof(::std::array<::std::uint8_t, 32> const &sk_bytes, ::std::array<::std::uint8_t, 32> const &block_hash, ::std::array<::std::uint8_t, 32> const &chain_state_hash);

// Verify a Groth16 participation proof.
bool hmp_verify_proof(::rust::Slice<::std::uint8_t const> proof_bytes, ::std::array<::std::uint8_t, 32> const &block_hash, ::std::array<::std::uint8_t, 32> const &commitment);

// Compute commitment for given inputs (used by prover and verifier).
::std::array<::std::uint8_t, 32> hmp_compute_commitment(::std::array<::std::uint8_t, 32> const &sk_bytes, ::std::array<::std::uint8_t, 32> const &block_hash, ::std::array<::std::uint8_t, 32> const &chain_state_hash);
} // namespace hmp

#ifdef __clang__
#pragma clang diagnostic pop
#endif // __clang__
