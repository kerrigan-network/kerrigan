#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <new>
#include <utility>

#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wshadow"
#ifdef __clang__
#pragma clang diagnostic ignored "-Wdollar-in-identifier-extension"
#endif // __clang__
#endif // __GNUC__

namespace rust {
inline namespace cxxbridge1 {
// #include "rust/cxx.h"

namespace {
template <typename T>
class impl;
} // namespace

#ifndef CXXBRIDGE1_RUST_ERROR
#define CXXBRIDGE1_RUST_ERROR
class Error final : public std::exception {
public:
  Error(const Error &);
  Error(Error &&) noexcept;
  ~Error() noexcept override;

  Error &operator=(const Error &) &;
  Error &operator=(Error &&) & noexcept;

  const char *what() const noexcept override;

private:
  Error() noexcept = default;
  friend impl<Error>;
  const char *msg;
  std::size_t len;
};
#endif // CXXBRIDGE1_RUST_ERROR

namespace repr {
struct PtrLen final {
  void *ptr;
  ::std::size_t len;
};
} // namespace repr

namespace detail {
template <typename T, typename = void *>
struct operator_new {
  void *operator()(::std::size_t sz) { return ::operator new(sz); }
};

template <typename T>
struct operator_new<T, decltype(T::operator new(sizeof(T)))> {
  void *operator()(::std::size_t sz) { return T::operator new(sz); }
};
} // namespace detail

template <typename T>
union ManuallyDrop {
  T value;
  ManuallyDrop(T &&value) : value(::std::move(value)) {}
  ~ManuallyDrop() {}
};

template <typename T>
union MaybeUninit {
  T value;
  void *operator new(::std::size_t sz) { return detail::operator_new<T>{}(sz); }
  MaybeUninit() {}
  ~MaybeUninit() {}
};

namespace {
template <>
class impl<Error> final {
public:
  static Error error(repr::PtrLen repr) noexcept {
    Error error;
    error.msg = static_cast<char const *>(repr.ptr);
    error.len = repr.len;
    return error;
  }
};
} // namespace
} // namespace cxxbridge1
} // namespace rust

namespace sapling {
namespace spec {
extern "C" {
void sapling$spec$cxxbridge1$tree_uncommitted(::std::array<::std::uint8_t, 32> *return$) noexcept;

void sapling$spec$cxxbridge1$merkle_hash(::std::size_t depth, ::std::array<::std::uint8_t, 32> const &lhs, ::std::array<::std::uint8_t, 32> const &rhs, ::std::array<::std::uint8_t, 32> *return$) noexcept;

void sapling$spec$cxxbridge1$to_scalar(::std::array<::std::uint8_t, 64> const &input, ::std::array<::std::uint8_t, 32> *return$) noexcept;

::rust::repr::PtrLen sapling$spec$cxxbridge1$ask_to_ak(::std::array<::std::uint8_t, 32> const &ask, ::std::array<::std::uint8_t, 32> *return$) noexcept;

::rust::repr::PtrLen sapling$spec$cxxbridge1$nsk_to_nk(::std::array<::std::uint8_t, 32> const &nsk, ::std::array<::std::uint8_t, 32> *return$) noexcept;

void sapling$spec$cxxbridge1$crh_ivk(::std::array<::std::uint8_t, 32> const &ak, ::std::array<::std::uint8_t, 32> const &nk, ::std::array<::std::uint8_t, 32> *return$) noexcept;

bool sapling$spec$cxxbridge1$check_diversifier(::std::array<::std::uint8_t, 11> *diversifier) noexcept;

::rust::repr::PtrLen sapling$spec$cxxbridge1$ivk_to_pkd(::std::array<::std::uint8_t, 32> const &ivk, ::std::array<::std::uint8_t, 11> *diversifier, ::std::array<::std::uint8_t, 32> *return$) noexcept;

void sapling$spec$cxxbridge1$generate_r(::std::array<::std::uint8_t, 32> *return$) noexcept;

::rust::repr::PtrLen sapling$spec$cxxbridge1$compute_nf(::std::array<::std::uint8_t, 11> const &diversifier, ::std::array<::std::uint8_t, 32> const &pk_d, ::std::uint64_t value, ::std::array<::std::uint8_t, 32> const &rcm, ::std::array<::std::uint8_t, 32> const &nk, ::std::uint64_t position, ::std::array<::std::uint8_t, 32> *return$) noexcept;

::rust::repr::PtrLen sapling$spec$cxxbridge1$compute_cmu(::std::array<::std::uint8_t, 11> *diversifier, ::std::array<::std::uint8_t, 32> const &pk_d, ::std::uint64_t value, ::std::array<::std::uint8_t, 32> const &rcm, ::std::array<::std::uint8_t, 32> *return$) noexcept;
} // extern "C"

::std::array<::std::uint8_t, 32> tree_uncommitted() noexcept {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  sapling$spec$cxxbridge1$tree_uncommitted(&return$.value);
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 32> merkle_hash(::std::size_t depth, ::std::array<::std::uint8_t, 32> const &lhs, ::std::array<::std::uint8_t, 32> const &rhs) noexcept {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  sapling$spec$cxxbridge1$merkle_hash(depth, lhs, rhs, &return$.value);
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 32> to_scalar(::std::array<::std::uint8_t, 64> const &input) noexcept {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  sapling$spec$cxxbridge1$to_scalar(input, &return$.value);
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 32> ask_to_ak(::std::array<::std::uint8_t, 32> const &ask) {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  ::rust::repr::PtrLen error$ = sapling$spec$cxxbridge1$ask_to_ak(ask, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 32> nsk_to_nk(::std::array<::std::uint8_t, 32> const &nsk) {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  ::rust::repr::PtrLen error$ = sapling$spec$cxxbridge1$nsk_to_nk(nsk, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 32> crh_ivk(::std::array<::std::uint8_t, 32> const &ak, ::std::array<::std::uint8_t, 32> const &nk) noexcept {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  sapling$spec$cxxbridge1$crh_ivk(ak, nk, &return$.value);
  return ::std::move(return$.value);
}

bool check_diversifier(::std::array<::std::uint8_t, 11> diversifier) noexcept {
  ::rust::ManuallyDrop<::std::array<::std::uint8_t, 11>> diversifier$(::std::move(diversifier));
  return sapling$spec$cxxbridge1$check_diversifier(&diversifier$.value);
}

::std::array<::std::uint8_t, 32> ivk_to_pkd(::std::array<::std::uint8_t, 32> const &ivk, ::std::array<::std::uint8_t, 11> diversifier) {
  ::rust::ManuallyDrop<::std::array<::std::uint8_t, 11>> diversifier$(::std::move(diversifier));
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  ::rust::repr::PtrLen error$ = sapling$spec$cxxbridge1$ivk_to_pkd(ivk, &diversifier$.value, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 32> generate_r() noexcept {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  sapling$spec$cxxbridge1$generate_r(&return$.value);
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 32> compute_nf(::std::array<::std::uint8_t, 11> const &diversifier, ::std::array<::std::uint8_t, 32> const &pk_d, ::std::uint64_t value, ::std::array<::std::uint8_t, 32> const &rcm, ::std::array<::std::uint8_t, 32> const &nk, ::std::uint64_t position) {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  ::rust::repr::PtrLen error$ = sapling$spec$cxxbridge1$compute_nf(diversifier, pk_d, value, rcm, nk, position, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 32> compute_cmu(::std::array<::std::uint8_t, 11> diversifier, ::std::array<::std::uint8_t, 32> const &pk_d, ::std::uint64_t value, ::std::array<::std::uint8_t, 32> const &rcm) {
  ::rust::ManuallyDrop<::std::array<::std::uint8_t, 11>> diversifier$(::std::move(diversifier));
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  ::rust::repr::PtrLen error$ = sapling$spec$cxxbridge1$compute_cmu(&diversifier$.value, pk_d, value, rcm, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}
} // namespace spec
} // namespace sapling
