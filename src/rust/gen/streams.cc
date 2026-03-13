#include "hash.h"
#include "streams.h"
#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <new>
#include <string>
#include <type_traits>
#include <utility>

#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wmissing-declarations"
#pragma GCC diagnostic ignored "-Wshadow"
#ifdef __clang__
#pragma clang diagnostic ignored "-Wdollar-in-identifier-extension"
#endif // __clang__
#endif // __GNUC__

namespace rust {
inline namespace cxxbridge1 {
// #include "rust/cxx.h"

#ifndef CXXBRIDGE1_IS_COMPLETE
#define CXXBRIDGE1_IS_COMPLETE
namespace detail {
namespace {
template <typename T, typename = std::size_t>
struct is_complete : std::false_type {};
template <typename T>
struct is_complete<T, decltype(sizeof(T))> : std::true_type {};
} // namespace
} // namespace detail
#endif // CXXBRIDGE1_IS_COMPLETE

namespace repr {
struct PtrLen final {
  void *ptr;
  ::std::size_t len;
};
} // namespace repr

namespace detail {
class Fail final {
  ::rust::repr::PtrLen &throw$;
public:
  Fail(::rust::repr::PtrLen &throw$) noexcept : throw$(throw$) {}
  void operator()(char const *) noexcept;
  void operator()(std::string const &) noexcept;
};
} // namespace detail

namespace {
template <bool> struct deleter_if {
  template <typename T> void operator()(T *) {}
};
template <> struct deleter_if<true> {
  template <typename T> void operator()(T *ptr) { ptr->~T(); }
};
} // namespace
} // namespace cxxbridge1

namespace behavior {
class missing {};
missing trycatch(...);

template <typename Try, typename Fail>
static typename ::std::enable_if<::std::is_same<
    decltype(trycatch(::std::declval<Try>(), ::std::declval<Fail>())),
    missing>::value>::type
trycatch(Try &&func, Fail &&fail) noexcept try {
  func();
} catch (::std::exception const &e) {
  fail(e.what());
}
} // namespace behavior
} // namespace rust

using RustDataStream = ::RustDataStream;
using CAutoFile = ::CAutoFile;
using CBufferedFile = ::CBufferedFile;
using CHashWriter = ::CHashWriter;
using CSizeComputer = ::CSizeComputer;

extern "C" {
::rust::repr::PtrLen cxxbridge1$RustDataStream$read_u8(::RustDataStream &self, ::std::uint8_t *pch, ::std::size_t nSize) noexcept {
  void (::RustDataStream::*read_u8$)(::std::uint8_t *, ::std::size_t) = &::RustDataStream::read_u8;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        (self.*read_u8$)(pch, nSize);
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

::rust::repr::PtrLen cxxbridge1$RustDataStream$write_u8(::RustDataStream &self, ::std::uint8_t const *pch, ::std::size_t nSize) noexcept {
  void (::RustDataStream::*write_u8$)(::std::uint8_t const *, ::std::size_t) = &::RustDataStream::write_u8;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        (self.*write_u8$)(pch, nSize);
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

::rust::repr::PtrLen cxxbridge1$CAutoFile$read_u8(::CAutoFile &self, ::std::uint8_t *pch, ::std::size_t nSize) noexcept {
  void (::CAutoFile::*read_u8$)(::std::uint8_t *, ::std::size_t) = &::CAutoFile::read_u8;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        (self.*read_u8$)(pch, nSize);
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

::rust::repr::PtrLen cxxbridge1$CAutoFile$write_u8(::CAutoFile &self, ::std::uint8_t const *pch, ::std::size_t nSize) noexcept {
  void (::CAutoFile::*write_u8$)(::std::uint8_t const *, ::std::size_t) = &::CAutoFile::write_u8;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        (self.*write_u8$)(pch, nSize);
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

::rust::repr::PtrLen cxxbridge1$CBufferedFile$read_u8(::CBufferedFile &self, ::std::uint8_t *pch, ::std::size_t nSize) noexcept {
  void (::CBufferedFile::*read_u8$)(::std::uint8_t *, ::std::size_t) = &::CBufferedFile::read_u8;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        (self.*read_u8$)(pch, nSize);
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

::rust::repr::PtrLen cxxbridge1$CHashWriter$write_u8(::CHashWriter &self, ::std::uint8_t const *pch, ::std::size_t nSize) noexcept {
  void (::CHashWriter::*write_u8$)(::std::uint8_t const *, ::std::size_t) = &::CHashWriter::write_u8;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        (self.*write_u8$)(pch, nSize);
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

::rust::repr::PtrLen cxxbridge1$CSizeComputer$write_u8(::CSizeComputer &self, ::std::uint8_t const *pch, ::std::size_t nSize) noexcept {
  void (::CSizeComputer::*write_u8$)(::std::uint8_t const *, ::std::size_t) = &::CSizeComputer::write_u8;
  ::rust::repr::PtrLen throw$;
  ::rust::behavior::trycatch(
      [&] {
        (self.*write_u8$)(pch, nSize);
        throw$.ptr = nullptr;
      },
      ::rust::detail::Fail(throw$));
  return throw$;
}

static_assert(::rust::detail::is_complete<::std::remove_extent<::RustDataStream>::type>::value, "definition of `::RustDataStream` is required");
static_assert(sizeof(::std::unique_ptr<::RustDataStream>) == sizeof(void *), "");
static_assert(alignof(::std::unique_ptr<::RustDataStream>) == alignof(void *), "");
void cxxbridge1$unique_ptr$RustDataStream$null(::std::unique_ptr<::RustDataStream> *ptr) noexcept {
  ::new (ptr) ::std::unique_ptr<::RustDataStream>();
}
void cxxbridge1$unique_ptr$RustDataStream$raw(::std::unique_ptr<::RustDataStream> *ptr, ::std::unique_ptr<::RustDataStream>::pointer raw) noexcept {
  ::new (ptr) ::std::unique_ptr<::RustDataStream>(raw);
}
::std::unique_ptr<::RustDataStream>::element_type const *cxxbridge1$unique_ptr$RustDataStream$get(::std::unique_ptr<::RustDataStream> const &ptr) noexcept {
  return ptr.get();
}
::std::unique_ptr<::RustDataStream>::pointer cxxbridge1$unique_ptr$RustDataStream$release(::std::unique_ptr<::RustDataStream> &ptr) noexcept {
  return ptr.release();
}
void cxxbridge1$unique_ptr$RustDataStream$drop(::std::unique_ptr<::RustDataStream> *ptr) noexcept {
  ::rust::deleter_if<::rust::detail::is_complete<::RustDataStream>::value>{}(ptr);
}

static_assert(::rust::detail::is_complete<::std::remove_extent<::CAutoFile>::type>::value, "definition of `::CAutoFile` is required");
static_assert(sizeof(::std::unique_ptr<::CAutoFile>) == sizeof(void *), "");
static_assert(alignof(::std::unique_ptr<::CAutoFile>) == alignof(void *), "");
void cxxbridge1$unique_ptr$CAutoFile$null(::std::unique_ptr<::CAutoFile> *ptr) noexcept {
  ::new (ptr) ::std::unique_ptr<::CAutoFile>();
}
void cxxbridge1$unique_ptr$CAutoFile$raw(::std::unique_ptr<::CAutoFile> *ptr, ::std::unique_ptr<::CAutoFile>::pointer raw) noexcept {
  ::new (ptr) ::std::unique_ptr<::CAutoFile>(raw);
}
::std::unique_ptr<::CAutoFile>::element_type const *cxxbridge1$unique_ptr$CAutoFile$get(::std::unique_ptr<::CAutoFile> const &ptr) noexcept {
  return ptr.get();
}
::std::unique_ptr<::CAutoFile>::pointer cxxbridge1$unique_ptr$CAutoFile$release(::std::unique_ptr<::CAutoFile> &ptr) noexcept {
  return ptr.release();
}
void cxxbridge1$unique_ptr$CAutoFile$drop(::std::unique_ptr<::CAutoFile> *ptr) noexcept {
  ::rust::deleter_if<::rust::detail::is_complete<::CAutoFile>::value>{}(ptr);
}

static_assert(::rust::detail::is_complete<::std::remove_extent<::CBufferedFile>::type>::value, "definition of `::CBufferedFile` is required");
static_assert(sizeof(::std::unique_ptr<::CBufferedFile>) == sizeof(void *), "");
static_assert(alignof(::std::unique_ptr<::CBufferedFile>) == alignof(void *), "");
void cxxbridge1$unique_ptr$CBufferedFile$null(::std::unique_ptr<::CBufferedFile> *ptr) noexcept {
  ::new (ptr) ::std::unique_ptr<::CBufferedFile>();
}
void cxxbridge1$unique_ptr$CBufferedFile$raw(::std::unique_ptr<::CBufferedFile> *ptr, ::std::unique_ptr<::CBufferedFile>::pointer raw) noexcept {
  ::new (ptr) ::std::unique_ptr<::CBufferedFile>(raw);
}
::std::unique_ptr<::CBufferedFile>::element_type const *cxxbridge1$unique_ptr$CBufferedFile$get(::std::unique_ptr<::CBufferedFile> const &ptr) noexcept {
  return ptr.get();
}
::std::unique_ptr<::CBufferedFile>::pointer cxxbridge1$unique_ptr$CBufferedFile$release(::std::unique_ptr<::CBufferedFile> &ptr) noexcept {
  return ptr.release();
}
void cxxbridge1$unique_ptr$CBufferedFile$drop(::std::unique_ptr<::CBufferedFile> *ptr) noexcept {
  ::rust::deleter_if<::rust::detail::is_complete<::CBufferedFile>::value>{}(ptr);
}

static_assert(::rust::detail::is_complete<::std::remove_extent<::CHashWriter>::type>::value, "definition of `::CHashWriter` is required");
static_assert(sizeof(::std::unique_ptr<::CHashWriter>) == sizeof(void *), "");
static_assert(alignof(::std::unique_ptr<::CHashWriter>) == alignof(void *), "");
void cxxbridge1$unique_ptr$CHashWriter$null(::std::unique_ptr<::CHashWriter> *ptr) noexcept {
  ::new (ptr) ::std::unique_ptr<::CHashWriter>();
}
void cxxbridge1$unique_ptr$CHashWriter$raw(::std::unique_ptr<::CHashWriter> *ptr, ::std::unique_ptr<::CHashWriter>::pointer raw) noexcept {
  ::new (ptr) ::std::unique_ptr<::CHashWriter>(raw);
}
::std::unique_ptr<::CHashWriter>::element_type const *cxxbridge1$unique_ptr$CHashWriter$get(::std::unique_ptr<::CHashWriter> const &ptr) noexcept {
  return ptr.get();
}
::std::unique_ptr<::CHashWriter>::pointer cxxbridge1$unique_ptr$CHashWriter$release(::std::unique_ptr<::CHashWriter> &ptr) noexcept {
  return ptr.release();
}
void cxxbridge1$unique_ptr$CHashWriter$drop(::std::unique_ptr<::CHashWriter> *ptr) noexcept {
  ::rust::deleter_if<::rust::detail::is_complete<::CHashWriter>::value>{}(ptr);
}

static_assert(::rust::detail::is_complete<::std::remove_extent<::CSizeComputer>::type>::value, "definition of `::CSizeComputer` is required");
static_assert(sizeof(::std::unique_ptr<::CSizeComputer>) == sizeof(void *), "");
static_assert(alignof(::std::unique_ptr<::CSizeComputer>) == alignof(void *), "");
void cxxbridge1$unique_ptr$CSizeComputer$null(::std::unique_ptr<::CSizeComputer> *ptr) noexcept {
  ::new (ptr) ::std::unique_ptr<::CSizeComputer>();
}
void cxxbridge1$unique_ptr$CSizeComputer$raw(::std::unique_ptr<::CSizeComputer> *ptr, ::std::unique_ptr<::CSizeComputer>::pointer raw) noexcept {
  ::new (ptr) ::std::unique_ptr<::CSizeComputer>(raw);
}
::std::unique_ptr<::CSizeComputer>::element_type const *cxxbridge1$unique_ptr$CSizeComputer$get(::std::unique_ptr<::CSizeComputer> const &ptr) noexcept {
  return ptr.get();
}
::std::unique_ptr<::CSizeComputer>::pointer cxxbridge1$unique_ptr$CSizeComputer$release(::std::unique_ptr<::CSizeComputer> &ptr) noexcept {
  return ptr.release();
}
void cxxbridge1$unique_ptr$CSizeComputer$drop(::std::unique_ptr<::CSizeComputer> *ptr) noexcept {
  ::rust::deleter_if<::rust::detail::is_complete<::CSizeComputer>::value>{}(ptr);
}
} // extern "C"
