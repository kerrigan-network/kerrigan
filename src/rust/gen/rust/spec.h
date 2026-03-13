#pragma once
#include <array>
#include <cstddef>
#include <cstdint>

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdollar-in-identifier-extension"
#endif // __clang__

namespace sapling {
namespace spec {
::std::array<::std::uint8_t, 32> tree_uncommitted() noexcept;

::std::array<::std::uint8_t, 32> merkle_hash(::std::size_t depth, ::std::array<::std::uint8_t, 32> const &lhs, ::std::array<::std::uint8_t, 32> const &rhs) noexcept;

::std::array<::std::uint8_t, 32> to_scalar(::std::array<::std::uint8_t, 64> const &input) noexcept;

::std::array<::std::uint8_t, 32> ask_to_ak(::std::array<::std::uint8_t, 32> const &ask);

::std::array<::std::uint8_t, 32> nsk_to_nk(::std::array<::std::uint8_t, 32> const &nsk);

::std::array<::std::uint8_t, 32> crh_ivk(::std::array<::std::uint8_t, 32> const &ak, ::std::array<::std::uint8_t, 32> const &nk) noexcept;

bool check_diversifier(::std::array<::std::uint8_t, 11> diversifier) noexcept;

::std::array<::std::uint8_t, 32> ivk_to_pkd(::std::array<::std::uint8_t, 32> const &ivk, ::std::array<::std::uint8_t, 11> diversifier);

::std::array<::std::uint8_t, 32> generate_r() noexcept;

::std::array<::std::uint8_t, 32> compute_nf(::std::array<::std::uint8_t, 11> const &diversifier, ::std::array<::std::uint8_t, 32> const &pk_d, ::std::uint64_t value, ::std::array<::std::uint8_t, 32> const &rcm, ::std::array<::std::uint8_t, 32> const &nk, ::std::uint64_t position);

::std::array<::std::uint8_t, 32> compute_cmu(::std::array<::std::uint8_t, 11> diversifier, ::std::array<::std::uint8_t, 32> const &pk_d, ::std::uint64_t value, ::std::array<::std::uint8_t, 32> const &rcm);
} // namespace spec
} // namespace sapling

#ifdef __clang__
#pragma clang diagnostic pop
#endif // __clang__
