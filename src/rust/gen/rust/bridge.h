#pragma once
#include "hash.h"
#include "streams.h"
#include "sapling/cache.h"
#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <iterator>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#if __cplusplus >= 201703L
#include <string_view>
#endif
#if __cplusplus >= 202002L
#include <ranges>
#endif

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdollar-in-identifier-extension"
#endif // __clang__

namespace rust {
inline namespace cxxbridge1 {
// #include "rust/cxx.h"

#ifndef CXXBRIDGE1_PANIC
#define CXXBRIDGE1_PANIC
template <typename Exception>
void panic [[noreturn]] (const char *msg);
#endif // CXXBRIDGE1_PANIC

namespace {
template <typename T>
class impl;
} // namespace

class String;

template <typename T>
::std::size_t size_of();
template <typename T>
::std::size_t align_of();

#ifndef CXXBRIDGE1_RUST_STR
#define CXXBRIDGE1_RUST_STR
class Str final {
public:
  Str() noexcept;
  Str(const String &) noexcept;
  Str(const std::string &);
  Str(const char *);
  Str(const char *, std::size_t);

  Str &operator=(const Str &) & noexcept = default;

  explicit operator std::string() const;
#if __cplusplus >= 201703L
  explicit operator std::string_view() const;
#endif

  const char *data() const noexcept;
  std::size_t size() const noexcept;
  std::size_t length() const noexcept;
  bool empty() const noexcept;

  Str(const Str &) noexcept = default;
  ~Str() noexcept = default;

  using iterator = const char *;
  using const_iterator = const char *;
  const_iterator begin() const noexcept;
  const_iterator end() const noexcept;
  const_iterator cbegin() const noexcept;
  const_iterator cend() const noexcept;

  bool operator==(const Str &) const noexcept;
  bool operator!=(const Str &) const noexcept;
  bool operator<(const Str &) const noexcept;
  bool operator<=(const Str &) const noexcept;
  bool operator>(const Str &) const noexcept;
  bool operator>=(const Str &) const noexcept;

  void swap(Str &) noexcept;

private:
  class uninit;
  Str(uninit) noexcept;
  friend impl<Str>;

  std::array<std::uintptr_t, 2> repr;
};
#endif // CXXBRIDGE1_RUST_STR

#ifndef CXXBRIDGE1_RUST_SLICE
#define CXXBRIDGE1_RUST_SLICE
namespace detail {
template <bool>
struct copy_assignable_if {};

template <>
struct copy_assignable_if<false> {
  copy_assignable_if() noexcept = default;
  copy_assignable_if(const copy_assignable_if &) noexcept = default;
  copy_assignable_if &operator=(const copy_assignable_if &) & noexcept = delete;
  copy_assignable_if &operator=(copy_assignable_if &&) & noexcept = default;
};
} // namespace detail

template <typename T>
class Slice final
    : private detail::copy_assignable_if<std::is_const<T>::value> {
public:
  using value_type = T;

  Slice() noexcept;
  Slice(T *, std::size_t count) noexcept;

  template <typename C>
  explicit Slice(C &c) : Slice(c.data(), c.size()) {}

  Slice &operator=(const Slice<T> &) & noexcept = default;
  Slice &operator=(Slice<T> &&) & noexcept = default;

  T *data() const noexcept;
  std::size_t size() const noexcept;
  std::size_t length() const noexcept;
  bool empty() const noexcept;

  T &operator[](std::size_t n) const noexcept;
  T &at(std::size_t n) const;
  T &front() const noexcept;
  T &back() const noexcept;

  Slice(const Slice<T> &) noexcept = default;
  ~Slice() noexcept = default;

  class iterator;
  iterator begin() const noexcept;
  iterator end() const noexcept;

  void swap(Slice &) noexcept;

private:
  class uninit;
  Slice(uninit) noexcept;
  friend impl<Slice>;
  friend void sliceInit(void *, const void *, std::size_t) noexcept;
  friend void *slicePtr(const void *) noexcept;
  friend std::size_t sliceLen(const void *) noexcept;

  std::array<std::uintptr_t, 2> repr;
};

#ifdef __cpp_deduction_guides
template <typename C>
explicit Slice(C &c)
    -> Slice<std::remove_reference_t<decltype(*std::declval<C>().data())>>;
#endif // __cpp_deduction_guides

template <typename T>
class Slice<T>::iterator final {
public:
#if __cplusplus >= 202002L
  using iterator_category = std::contiguous_iterator_tag;
#else
  using iterator_category = std::random_access_iterator_tag;
#endif
  using value_type = T;
  using difference_type = std::ptrdiff_t;
  using pointer = typename std::add_pointer<T>::type;
  using reference = typename std::add_lvalue_reference<T>::type;

  reference operator*() const noexcept;
  pointer operator->() const noexcept;
  reference operator[](difference_type) const noexcept;

  iterator &operator++() noexcept;
  iterator operator++(int) noexcept;
  iterator &operator--() noexcept;
  iterator operator--(int) noexcept;

  iterator &operator+=(difference_type) noexcept;
  iterator &operator-=(difference_type) noexcept;
  iterator operator+(difference_type) const noexcept;
  friend inline iterator operator+(difference_type lhs, iterator rhs) noexcept {
    return rhs + lhs;
  }
  iterator operator-(difference_type) const noexcept;
  difference_type operator-(const iterator &) const noexcept;

  bool operator==(const iterator &) const noexcept;
  bool operator!=(const iterator &) const noexcept;
  bool operator<(const iterator &) const noexcept;
  bool operator<=(const iterator &) const noexcept;
  bool operator>(const iterator &) const noexcept;
  bool operator>=(const iterator &) const noexcept;

private:
  friend class Slice;
  void *pos;
  std::size_t stride;
};

#if __cplusplus >= 202002L
static_assert(std::ranges::contiguous_range<rust::Slice<const uint8_t>>);
static_assert(std::contiguous_iterator<rust::Slice<const uint8_t>::iterator>);
#endif

template <typename T>
Slice<T>::Slice() noexcept {
  sliceInit(this, reinterpret_cast<void *>(align_of<T>()), 0);
}

template <typename T>
Slice<T>::Slice(T *s, std::size_t count) noexcept {
  assert(s != nullptr || count == 0);
  sliceInit(this,
            s == nullptr && count == 0
                ? reinterpret_cast<void *>(align_of<T>())
                : const_cast<typename std::remove_const<T>::type *>(s),
            count);
}

template <typename T>
T *Slice<T>::data() const noexcept {
  return reinterpret_cast<T *>(slicePtr(this));
}

template <typename T>
std::size_t Slice<T>::size() const noexcept {
  return sliceLen(this);
}

template <typename T>
std::size_t Slice<T>::length() const noexcept {
  return this->size();
}

template <typename T>
bool Slice<T>::empty() const noexcept {
  return this->size() == 0;
}

template <typename T>
T &Slice<T>::operator[](std::size_t n) const noexcept {
  assert(n < this->size());
  auto ptr = static_cast<char *>(slicePtr(this)) + size_of<T>() * n;
  return *reinterpret_cast<T *>(ptr);
}

template <typename T>
T &Slice<T>::at(std::size_t n) const {
  if (n >= this->size()) {
    panic<std::out_of_range>("rust::Slice index out of range");
  }
  return (*this)[n];
}

template <typename T>
T &Slice<T>::front() const noexcept {
  assert(!this->empty());
  return (*this)[0];
}

template <typename T>
T &Slice<T>::back() const noexcept {
  assert(!this->empty());
  return (*this)[this->size() - 1];
}

template <typename T>
typename Slice<T>::iterator::reference
Slice<T>::iterator::operator*() const noexcept {
  return *static_cast<T *>(this->pos);
}

template <typename T>
typename Slice<T>::iterator::pointer
Slice<T>::iterator::operator->() const noexcept {
  return static_cast<T *>(this->pos);
}

template <typename T>
typename Slice<T>::iterator::reference Slice<T>::iterator::operator[](
    typename Slice<T>::iterator::difference_type n) const noexcept {
  auto ptr = static_cast<char *>(this->pos) + this->stride * n;
  return *reinterpret_cast<T *>(ptr);
}

template <typename T>
typename Slice<T>::iterator &Slice<T>::iterator::operator++() noexcept {
  this->pos = static_cast<char *>(this->pos) + this->stride;
  return *this;
}

template <typename T>
typename Slice<T>::iterator Slice<T>::iterator::operator++(int) noexcept {
  auto ret = iterator(*this);
  this->pos = static_cast<char *>(this->pos) + this->stride;
  return ret;
}

template <typename T>
typename Slice<T>::iterator &Slice<T>::iterator::operator--() noexcept {
  this->pos = static_cast<char *>(this->pos) - this->stride;
  return *this;
}

template <typename T>
typename Slice<T>::iterator Slice<T>::iterator::operator--(int) noexcept {
  auto ret = iterator(*this);
  this->pos = static_cast<char *>(this->pos) - this->stride;
  return ret;
}

template <typename T>
typename Slice<T>::iterator &Slice<T>::iterator::operator+=(
    typename Slice<T>::iterator::difference_type n) noexcept {
  this->pos = static_cast<char *>(this->pos) + this->stride * n;
  return *this;
}

template <typename T>
typename Slice<T>::iterator &Slice<T>::iterator::operator-=(
    typename Slice<T>::iterator::difference_type n) noexcept {
  this->pos = static_cast<char *>(this->pos) - this->stride * n;
  return *this;
}

template <typename T>
typename Slice<T>::iterator Slice<T>::iterator::operator+(
    typename Slice<T>::iterator::difference_type n) const noexcept {
  auto ret = iterator(*this);
  ret.pos = static_cast<char *>(this->pos) + this->stride * n;
  return ret;
}

template <typename T>
typename Slice<T>::iterator Slice<T>::iterator::operator-(
    typename Slice<T>::iterator::difference_type n) const noexcept {
  auto ret = iterator(*this);
  ret.pos = static_cast<char *>(this->pos) - this->stride * n;
  return ret;
}

template <typename T>
typename Slice<T>::iterator::difference_type
Slice<T>::iterator::operator-(const iterator &other) const noexcept {
  auto diff = std::distance(static_cast<char *>(other.pos),
                            static_cast<char *>(this->pos));
  return diff / static_cast<typename Slice<T>::iterator::difference_type>(
                    this->stride);
}

template <typename T>
bool Slice<T>::iterator::operator==(const iterator &other) const noexcept {
  return this->pos == other.pos;
}

template <typename T>
bool Slice<T>::iterator::operator!=(const iterator &other) const noexcept {
  return this->pos != other.pos;
}

template <typename T>
bool Slice<T>::iterator::operator<(const iterator &other) const noexcept {
  return this->pos < other.pos;
}

template <typename T>
bool Slice<T>::iterator::operator<=(const iterator &other) const noexcept {
  return this->pos <= other.pos;
}

template <typename T>
bool Slice<T>::iterator::operator>(const iterator &other) const noexcept {
  return this->pos > other.pos;
}

template <typename T>
bool Slice<T>::iterator::operator>=(const iterator &other) const noexcept {
  return this->pos >= other.pos;
}

template <typename T>
typename Slice<T>::iterator Slice<T>::begin() const noexcept {
  iterator it;
  it.pos = slicePtr(this);
  it.stride = size_of<T>();
  return it;
}

template <typename T>
typename Slice<T>::iterator Slice<T>::end() const noexcept {
  iterator it = this->begin();
  it.pos = static_cast<char *>(it.pos) + it.stride * this->size();
  return it;
}

template <typename T>
void Slice<T>::swap(Slice &rhs) noexcept {
  std::swap(*this, rhs);
}
#endif // CXXBRIDGE1_RUST_SLICE

#ifndef CXXBRIDGE1_RUST_BOX
#define CXXBRIDGE1_RUST_BOX
template <typename T>
class Box final {
public:
  using element_type = T;
  using const_pointer =
      typename std::add_pointer<typename std::add_const<T>::type>::type;
  using pointer = typename std::add_pointer<T>::type;

  Box() = delete;
  Box(Box &&) noexcept;
  ~Box() noexcept;

  explicit Box(const T &);
  explicit Box(T &&);

  Box &operator=(Box &&) & noexcept;

  const T *operator->() const noexcept;
  const T &operator*() const noexcept;
  T *operator->() noexcept;
  T &operator*() noexcept;

  template <typename... Fields>
  static Box in_place(Fields &&...);

  void swap(Box &) noexcept;

  static Box from_raw(T *) noexcept;

  T *into_raw() noexcept;

  /* Deprecated */ using value_type = element_type;

private:
  class uninit;
  class allocation;
  Box(uninit) noexcept;
  void drop() noexcept;

  friend void swap(Box &lhs, Box &rhs) noexcept { lhs.swap(rhs); }

  T *ptr;
};

template <typename T>
class Box<T>::uninit {};

template <typename T>
class Box<T>::allocation {
  static T *alloc() noexcept;
  static void dealloc(T *) noexcept;

public:
  allocation() noexcept : ptr(alloc()) {}
  ~allocation() noexcept {
    if (this->ptr) {
      dealloc(this->ptr);
    }
  }
  T *ptr;
};

template <typename T>
Box<T>::Box(Box &&other) noexcept : ptr(other.ptr) {
  other.ptr = nullptr;
}

template <typename T>
Box<T>::Box(const T &val) {
  allocation alloc;
  ::new (alloc.ptr) T(val);
  this->ptr = alloc.ptr;
  alloc.ptr = nullptr;
}

template <typename T>
Box<T>::Box(T &&val) {
  allocation alloc;
  ::new (alloc.ptr) T(std::move(val));
  this->ptr = alloc.ptr;
  alloc.ptr = nullptr;
}

template <typename T>
Box<T>::~Box() noexcept {
  if (this->ptr) {
    this->drop();
  }
}

template <typename T>
Box<T> &Box<T>::operator=(Box &&other) & noexcept {
  if (this->ptr) {
    this->drop();
  }
  this->ptr = other.ptr;
  other.ptr = nullptr;
  return *this;
}

template <typename T>
const T *Box<T>::operator->() const noexcept {
  return this->ptr;
}

template <typename T>
const T &Box<T>::operator*() const noexcept {
  return *this->ptr;
}

template <typename T>
T *Box<T>::operator->() noexcept {
  return this->ptr;
}

template <typename T>
T &Box<T>::operator*() noexcept {
  return *this->ptr;
}

template <typename T>
template <typename... Fields>
Box<T> Box<T>::in_place(Fields &&...fields) {
  allocation alloc;
  auto ptr = alloc.ptr;
  ::new (ptr) T{std::forward<Fields>(fields)...};
  alloc.ptr = nullptr;
  return from_raw(ptr);
}

template <typename T>
void Box<T>::swap(Box &rhs) noexcept {
  using std::swap;
  swap(this->ptr, rhs.ptr);
}

template <typename T>
Box<T> Box<T>::from_raw(T *raw) noexcept {
  Box box = uninit{};
  box.ptr = raw;
  return box;
}

template <typename T>
T *Box<T>::into_raw() noexcept {
  T *raw = this->ptr;
  this->ptr = nullptr;
  return raw;
}

template <typename T>
Box<T>::Box(uninit) noexcept {}
#endif // CXXBRIDGE1_RUST_BOX

#ifndef CXXBRIDGE1_RUST_BITCOPY_T
#define CXXBRIDGE1_RUST_BITCOPY_T
struct unsafe_bitcopy_t final {
  explicit unsafe_bitcopy_t() = default;
};
#endif // CXXBRIDGE1_RUST_BITCOPY_T

#ifndef CXXBRIDGE1_RUST_VEC
#define CXXBRIDGE1_RUST_VEC
template <typename T>
class Vec final {
public:
  using value_type = T;

  Vec() noexcept;
  Vec(std::initializer_list<T>);
  Vec(const Vec &);
  Vec(Vec &&) noexcept;
  ~Vec() noexcept;

  Vec &operator=(Vec &&) & noexcept;
  Vec &operator=(const Vec &) &;

  std::size_t size() const noexcept;
  bool empty() const noexcept;
  const T *data() const noexcept;
  T *data() noexcept;
  std::size_t capacity() const noexcept;

  const T &operator[](std::size_t n) const noexcept;
  const T &at(std::size_t n) const;
  const T &front() const noexcept;
  const T &back() const noexcept;

  T &operator[](std::size_t n) noexcept;
  T &at(std::size_t n);
  T &front() noexcept;
  T &back() noexcept;

  void reserve(std::size_t new_cap);
  void push_back(const T &value);
  void push_back(T &&value);
  template <typename... Args>
  void emplace_back(Args &&...args);
  void truncate(std::size_t len);
  void clear();

  using iterator = typename Slice<T>::iterator;
  iterator begin() noexcept;
  iterator end() noexcept;

  using const_iterator = typename Slice<const T>::iterator;
  const_iterator begin() const noexcept;
  const_iterator end() const noexcept;
  const_iterator cbegin() const noexcept;
  const_iterator cend() const noexcept;

  void swap(Vec &) noexcept;

  Vec(unsafe_bitcopy_t, const Vec &) noexcept;

private:
  void reserve_total(std::size_t new_cap) noexcept;
  void set_len(std::size_t len) noexcept;
  void drop() noexcept;

  friend void swap(Vec &lhs, Vec &rhs) noexcept { lhs.swap(rhs); }

  std::array<std::uintptr_t, 3> repr;
};

template <typename T>
Vec<T>::Vec(std::initializer_list<T> init) : Vec{} {
  this->reserve_total(init.size());
  std::move(init.begin(), init.end(), std::back_inserter(*this));
}

template <typename T>
Vec<T>::Vec(const Vec &other) : Vec() {
  this->reserve_total(other.size());
  std::copy(other.begin(), other.end(), std::back_inserter(*this));
}

template <typename T>
Vec<T>::Vec(Vec &&other) noexcept : repr(other.repr) {
  new (&other) Vec();
}

template <typename T>
Vec<T>::~Vec() noexcept {
  this->drop();
}

template <typename T>
Vec<T> &Vec<T>::operator=(Vec &&other) & noexcept {
  this->drop();
  this->repr = other.repr;
  new (&other) Vec();
  return *this;
}

template <typename T>
Vec<T> &Vec<T>::operator=(const Vec &other) & {
  if (this != &other) {
    this->drop();
    new (this) Vec(other);
  }
  return *this;
}

template <typename T>
bool Vec<T>::empty() const noexcept {
  return this->size() == 0;
}

template <typename T>
T *Vec<T>::data() noexcept {
  return const_cast<T *>(const_cast<const Vec<T> *>(this)->data());
}

template <typename T>
const T &Vec<T>::operator[](std::size_t n) const noexcept {
  assert(n < this->size());
  auto data = reinterpret_cast<const char *>(this->data());
  return *reinterpret_cast<const T *>(data + n * size_of<T>());
}

template <typename T>
const T &Vec<T>::at(std::size_t n) const {
  if (n >= this->size()) {
    panic<std::out_of_range>("rust::Vec index out of range");
  }
  return (*this)[n];
}

template <typename T>
const T &Vec<T>::front() const noexcept {
  assert(!this->empty());
  return (*this)[0];
}

template <typename T>
const T &Vec<T>::back() const noexcept {
  assert(!this->empty());
  return (*this)[this->size() - 1];
}

template <typename T>
T &Vec<T>::operator[](std::size_t n) noexcept {
  assert(n < this->size());
  auto data = reinterpret_cast<char *>(this->data());
  return *reinterpret_cast<T *>(data + n * size_of<T>());
}

template <typename T>
T &Vec<T>::at(std::size_t n) {
  if (n >= this->size()) {
    panic<std::out_of_range>("rust::Vec index out of range");
  }
  return (*this)[n];
}

template <typename T>
T &Vec<T>::front() noexcept {
  assert(!this->empty());
  return (*this)[0];
}

template <typename T>
T &Vec<T>::back() noexcept {
  assert(!this->empty());
  return (*this)[this->size() - 1];
}

template <typename T>
void Vec<T>::reserve(std::size_t new_cap) {
  this->reserve_total(new_cap);
}

template <typename T>
void Vec<T>::push_back(const T &value) {
  this->emplace_back(value);
}

template <typename T>
void Vec<T>::push_back(T &&value) {
  this->emplace_back(std::move(value));
}

template <typename T>
template <typename... Args>
void Vec<T>::emplace_back(Args &&...args) {
  auto size = this->size();
  this->reserve_total(size + 1);
  ::new (reinterpret_cast<T *>(reinterpret_cast<char *>(this->data()) +
                               size * size_of<T>()))
      T(std::forward<Args>(args)...);
  this->set_len(size + 1);
}

template <typename T>
void Vec<T>::clear() {
  this->truncate(0);
}

template <typename T>
typename Vec<T>::iterator Vec<T>::begin() noexcept {
  return Slice<T>(this->data(), this->size()).begin();
}

template <typename T>
typename Vec<T>::iterator Vec<T>::end() noexcept {
  return Slice<T>(this->data(), this->size()).end();
}

template <typename T>
typename Vec<T>::const_iterator Vec<T>::begin() const noexcept {
  return this->cbegin();
}

template <typename T>
typename Vec<T>::const_iterator Vec<T>::end() const noexcept {
  return this->cend();
}

template <typename T>
typename Vec<T>::const_iterator Vec<T>::cbegin() const noexcept {
  return Slice<const T>(this->data(), this->size()).begin();
}

template <typename T>
typename Vec<T>::const_iterator Vec<T>::cend() const noexcept {
  return Slice<const T>(this->data(), this->size()).end();
}

template <typename T>
void Vec<T>::swap(Vec &rhs) noexcept {
  using std::swap;
  swap(this->repr, rhs.repr);
}

template <typename T>
Vec<T>::Vec(unsafe_bitcopy_t, const Vec &bits) noexcept : repr(bits.repr) {}
#endif // CXXBRIDGE1_RUST_VEC

#ifndef CXXBRIDGE1_RUST_OPAQUE
#define CXXBRIDGE1_RUST_OPAQUE
class Opaque {
public:
  Opaque() = delete;
  Opaque(const Opaque &) = delete;
  ~Opaque() = delete;
};
#endif // CXXBRIDGE1_RUST_OPAQUE

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

#ifndef CXXBRIDGE1_LAYOUT
#define CXXBRIDGE1_LAYOUT
class layout {
  template <typename T>
  friend std::size_t size_of();
  template <typename T>
  friend std::size_t align_of();
  template <typename T>
  static typename std::enable_if<std::is_base_of<Opaque, T>::value,
                                 std::size_t>::type
  do_size_of() {
    return T::layout::size();
  }
  template <typename T>
  static typename std::enable_if<!std::is_base_of<Opaque, T>::value,
                                 std::size_t>::type
  do_size_of() {
    return sizeof(T);
  }
  template <typename T>
  static
      typename std::enable_if<detail::is_complete<T>::value, std::size_t>::type
      size_of() {
    return do_size_of<T>();
  }
  template <typename T>
  static typename std::enable_if<std::is_base_of<Opaque, T>::value,
                                 std::size_t>::type
  do_align_of() {
    return T::layout::align();
  }
  template <typename T>
  static typename std::enable_if<!std::is_base_of<Opaque, T>::value,
                                 std::size_t>::type
  do_align_of() {
    return alignof(T);
  }
  template <typename T>
  static
      typename std::enable_if<detail::is_complete<T>::value, std::size_t>::type
      align_of() {
    return do_align_of<T>();
  }
};

template <typename T>
std::size_t size_of() {
  return layout::size_of<T>();
}

template <typename T>
std::size_t align_of() {
  return layout::align_of<T>();
}
#endif // CXXBRIDGE1_LAYOUT
} // namespace cxxbridge1
} // namespace rust

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
::std::array<::std::uint8_t, 11> diversifier_index(::std::array<::std::uint8_t, 32> dk, ::std::array<::std::uint8_t, 11> d) noexcept;

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
::std::array<::std::uint8_t, 32> witness_root(::sapling::tree::SaplingWitness const &wit) noexcept;

// Get the position of the witnessed leaf.
::std::uint64_t witness_position(::sapling::tree::SaplingWitness const &wit) noexcept;

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
