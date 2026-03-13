#include "hash.h"
#include "streams.h"
#include "sapling/cache.h"
#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <exception>
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

template <bool> struct deleter_if {
  template <typename T> void operator()(T *) {}
};
template <> struct deleter_if<true> {
  template <typename T> void operator()(T *ptr) { ptr->~T(); }
};
} // namespace
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
extern "C" {
::std::size_t stream$cxxbridge1$CppStream$operator$sizeof() noexcept;
::std::size_t stream$cxxbridge1$CppStream$operator$alignof() noexcept;

::stream::CppStream *stream$cxxbridge1$from_data(::RustDataStream &stream) noexcept;

::stream::CppStream *stream$cxxbridge1$from_auto_file(::CAutoFile &file) noexcept;

::stream::CppStream *stream$cxxbridge1$from_buffered_file(::CBufferedFile &file) noexcept;

::stream::CppStream *stream$cxxbridge1$from_hash_writer(::CHashWriter &writer) noexcept;

::stream::CppStream *stream$cxxbridge1$from_size_computer(::CSizeComputer &sc) noexcept;
} // extern "C"
} // namespace stream

namespace consensus {
extern "C" {
::std::size_t consensus$cxxbridge1$Network$operator$sizeof() noexcept;
::std::size_t consensus$cxxbridge1$Network$operator$alignof() noexcept;

::rust::repr::PtrLen consensus$cxxbridge1$network(::rust::Str network, ::std::int32_t overwinter, ::std::int32_t sapling, ::std::int32_t blossom, ::std::int32_t heartwood, ::std::int32_t canopy, ::std::int32_t nu5, ::std::int32_t nu6, ::std::int32_t nu6_1, ::rust::Box<::consensus::Network> *return$) noexcept;
} // extern "C"
} // namespace consensus

namespace libkerrigan {
extern "C" {
::libkerrigan::BundleValidityCache *libkerrigan$cxxbridge1$NewBundleValidityCache(::rust::Str kind, ::std::size_t bytes) noexcept {
  ::std::unique_ptr<::libkerrigan::BundleValidityCache> (*NewBundleValidityCache$)(::rust::Str, ::std::size_t) = ::libkerrigan::NewBundleValidityCache;
  return NewBundleValidityCache$(kind, bytes).release();
}

void libkerrigan$cxxbridge1$BundleValidityCache$insert(::libkerrigan::BundleValidityCache &self, ::std::array<::std::uint8_t, 32> *entry) noexcept {
  void (::libkerrigan::BundleValidityCache::*insert$)(::std::array<::std::uint8_t, 32>) = &::libkerrigan::BundleValidityCache::insert;
  (self.*insert$)(::std::move(*entry));
}

bool libkerrigan$cxxbridge1$BundleValidityCache$contains(::libkerrigan::BundleValidityCache const &self, ::std::array<::std::uint8_t, 32> const &entry, bool erase) noexcept {
  bool (::libkerrigan::BundleValidityCache::*contains$)(::std::array<::std::uint8_t, 32> const &, bool) const = &::libkerrigan::BundleValidityCache::contains;
  return (self.*contains$)(entry, erase);
}
} // extern "C"
} // namespace libkerrigan

namespace bundlecache {
extern "C" {
void bundlecache$cxxbridge1$bundlecache_init(::std::size_t cache_bytes) noexcept;
} // extern "C"
} // namespace bundlecache

namespace sapling {
extern "C" {
::std::size_t sapling$cxxbridge1$Spend$operator$sizeof() noexcept;
::std::size_t sapling$cxxbridge1$Spend$operator$alignof() noexcept;

::rust::repr::PtrLen sapling$cxxbridge1$parse_v4_sapling_spend(::rust::Slice<::std::uint8_t const> bytes, ::rust::Box<::sapling::Spend> *return$) noexcept;

void sapling$cxxbridge1$Spend$cv(::sapling::Spend const &self, ::std::array<::std::uint8_t, 32> *return$) noexcept;

void sapling$cxxbridge1$Spend$anchor(::sapling::Spend const &self, ::std::array<::std::uint8_t, 32> *return$) noexcept;

void sapling$cxxbridge1$Spend$nullifier(::sapling::Spend const &self, ::std::array<::std::uint8_t, 32> *return$) noexcept;

void sapling$cxxbridge1$Spend$rk(::sapling::Spend const &self, ::std::array<::std::uint8_t, 32> *return$) noexcept;

void sapling$cxxbridge1$Spend$zkproof(::sapling::Spend const &self, ::std::array<::std::uint8_t, 192> *return$) noexcept;

void sapling$cxxbridge1$Spend$spend_auth_sig(::sapling::Spend const &self, ::std::array<::std::uint8_t, 64> *return$) noexcept;
::std::size_t sapling$cxxbridge1$Output$operator$sizeof() noexcept;
::std::size_t sapling$cxxbridge1$Output$operator$alignof() noexcept;

::rust::repr::PtrLen sapling$cxxbridge1$parse_v4_sapling_output(::rust::Slice<::std::uint8_t const> bytes, ::rust::Box<::sapling::Output> *return$) noexcept;

void sapling$cxxbridge1$Output$cv(::sapling::Output const &self, ::std::array<::std::uint8_t, 32> *return$) noexcept;

void sapling$cxxbridge1$Output$cmu(::sapling::Output const &self, ::std::array<::std::uint8_t, 32> *return$) noexcept;

void sapling$cxxbridge1$Output$ephemeral_key(::sapling::Output const &self, ::std::array<::std::uint8_t, 32> *return$) noexcept;

void sapling$cxxbridge1$Output$enc_ciphertext(::sapling::Output const &self, ::std::array<::std::uint8_t, 580> *return$) noexcept;

void sapling$cxxbridge1$Output$out_ciphertext(::sapling::Output const &self, ::std::array<::std::uint8_t, 80> *return$) noexcept;

void sapling$cxxbridge1$Output$zkproof(::sapling::Output const &self, ::std::array<::std::uint8_t, 192> *return$) noexcept;

::rust::repr::PtrLen sapling$cxxbridge1$Output$serialize_v4(::sapling::Output const &self, ::stream::CppStream &stream) noexcept;
::std::size_t sapling$cxxbridge1$Bundle$operator$sizeof() noexcept;
::std::size_t sapling$cxxbridge1$Bundle$operator$alignof() noexcept;

::sapling::Bundle *sapling$cxxbridge1$none_sapling_bundle() noexcept;

::sapling::Bundle *sapling$cxxbridge1$Bundle$box_clone(::sapling::Bundle const &self) noexcept;

::rust::repr::PtrLen sapling$cxxbridge1$parse_v5_sapling_bundle(::stream::CppStream &stream, ::rust::Box<::sapling::Bundle> *return$) noexcept;

::rust::repr::PtrLen sapling$cxxbridge1$Bundle$serialize_v4_components(::sapling::Bundle const &self, ::stream::CppStream &stream, bool has_sapling) noexcept;

::rust::repr::PtrLen sapling$cxxbridge1$Bundle$serialize_v5(::sapling::Bundle const &self, ::stream::CppStream &stream) noexcept;

::std::size_t sapling$cxxbridge1$Bundle$recursive_dynamic_usage(::sapling::Bundle const &self) noexcept;

bool sapling$cxxbridge1$Bundle$is_present(::sapling::Bundle const &self) noexcept;

void sapling$cxxbridge1$Bundle$spends(::sapling::Bundle const &self, ::rust::Vec<::sapling::Spend> *return$) noexcept;

void sapling$cxxbridge1$Bundle$outputs(::sapling::Bundle const &self, ::rust::Vec<::sapling::Output> *return$) noexcept;

::std::size_t sapling$cxxbridge1$Bundle$num_spends(::sapling::Bundle const &self) noexcept;

::std::size_t sapling$cxxbridge1$Bundle$num_outputs(::sapling::Bundle const &self) noexcept;

::std::int64_t sapling$cxxbridge1$Bundle$value_balance_zat(::sapling::Bundle const &self) noexcept;

::rust::repr::PtrLen sapling$cxxbridge1$Bundle$binding_sig(::sapling::Bundle const &self, ::std::array<::std::uint8_t, 64> *return$) noexcept;
::std::size_t sapling$cxxbridge1$BundleAssembler$operator$sizeof() noexcept;
::std::size_t sapling$cxxbridge1$BundleAssembler$operator$alignof() noexcept;

::sapling::BundleAssembler *sapling$cxxbridge1$new_bundle_assembler() noexcept;

::rust::repr::PtrLen sapling$cxxbridge1$parse_v4_sapling_components(::stream::CppStream &stream, bool has_sapling, ::rust::Box<::sapling::BundleAssembler> *return$) noexcept;

bool sapling$cxxbridge1$BundleAssembler$have_actions(::sapling::BundleAssembler const &self) noexcept;

::sapling::Bundle *sapling$cxxbridge1$finish_bundle_assembly(::sapling::BundleAssembler *assembler, ::std::array<::std::uint8_t, 64> *binding_sig) noexcept;
::std::size_t sapling$cxxbridge1$Builder$operator$sizeof() noexcept;
::std::size_t sapling$cxxbridge1$Builder$operator$alignof() noexcept;

::rust::repr::PtrLen sapling$cxxbridge1$new_sapling_builder(::consensus::Network const &network, ::std::uint32_t height, ::std::array<::std::uint8_t, 32> *anchor, bool coinbase, ::rust::Box<::sapling::Builder> *return$) noexcept;

::rust::repr::PtrLen sapling$cxxbridge1$Builder$add_spend(::sapling::Builder &self, ::rust::Slice<::std::uint8_t const> extsk, ::std::array<::std::uint8_t, 43> *recipient, ::std::uint64_t value, ::std::array<::std::uint8_t, 32> *rcm, ::std::array<::std::uint8_t, 1065> *merkle_path) noexcept;

::rust::repr::PtrLen sapling$cxxbridge1$Builder$add_recipient(::sapling::Builder &self, ::std::array<::std::uint8_t, 32> *ovk, ::std::array<::std::uint8_t, 43> *to, ::std::uint64_t value, ::std::array<::std::uint8_t, 512> *memo) noexcept;

::rust::repr::PtrLen sapling$cxxbridge1$Builder$add_recipient_no_ovk(::sapling::Builder &self, ::std::array<::std::uint8_t, 43> *to, ::std::uint64_t value, ::std::array<::std::uint8_t, 512> *memo) noexcept;

::rust::repr::PtrLen sapling$cxxbridge1$build_sapling_bundle(::sapling::Builder *builder, ::rust::Box<::sapling::UnauthorizedBundle> *return$) noexcept;
::std::size_t sapling$cxxbridge1$UnauthorizedBundle$operator$sizeof() noexcept;
::std::size_t sapling$cxxbridge1$UnauthorizedBundle$operator$alignof() noexcept;

::std::size_t sapling$cxxbridge1$UnauthorizedBundle$num_spends(::sapling::UnauthorizedBundle const &self) noexcept;

::std::size_t sapling$cxxbridge1$UnauthorizedBundle$num_outputs(::sapling::UnauthorizedBundle const &self) noexcept;

::std::int64_t sapling$cxxbridge1$UnauthorizedBundle$value_balance_zat(::sapling::UnauthorizedBundle const &self) noexcept;

::rust::repr::PtrLen sapling$cxxbridge1$UnauthorizedBundle$spend_cv(::sapling::UnauthorizedBundle const &self, ::std::size_t i, ::std::array<::std::uint8_t, 32> *return$) noexcept;

::rust::repr::PtrLen sapling$cxxbridge1$UnauthorizedBundle$spend_anchor(::sapling::UnauthorizedBundle const &self, ::std::size_t i, ::std::array<::std::uint8_t, 32> *return$) noexcept;

::rust::repr::PtrLen sapling$cxxbridge1$UnauthorizedBundle$spend_nullifier(::sapling::UnauthorizedBundle const &self, ::std::size_t i, ::std::array<::std::uint8_t, 32> *return$) noexcept;

::rust::repr::PtrLen sapling$cxxbridge1$UnauthorizedBundle$spend_rk(::sapling::UnauthorizedBundle const &self, ::std::size_t i, ::std::array<::std::uint8_t, 32> *return$) noexcept;

::rust::repr::PtrLen sapling$cxxbridge1$UnauthorizedBundle$spend_zkproof(::sapling::UnauthorizedBundle const &self, ::std::size_t i, ::std::array<::std::uint8_t, 192> *return$) noexcept;

::rust::repr::PtrLen sapling$cxxbridge1$UnauthorizedBundle$output_cv(::sapling::UnauthorizedBundle const &self, ::std::size_t i, ::std::array<::std::uint8_t, 32> *return$) noexcept;

::rust::repr::PtrLen sapling$cxxbridge1$UnauthorizedBundle$output_cmu(::sapling::UnauthorizedBundle const &self, ::std::size_t i, ::std::array<::std::uint8_t, 32> *return$) noexcept;

::rust::repr::PtrLen sapling$cxxbridge1$UnauthorizedBundle$output_ephemeral_key(::sapling::UnauthorizedBundle const &self, ::std::size_t i, ::std::array<::std::uint8_t, 32> *return$) noexcept;

::rust::repr::PtrLen sapling$cxxbridge1$UnauthorizedBundle$output_enc_ciphertext(::sapling::UnauthorizedBundle const &self, ::std::size_t i, ::std::array<::std::uint8_t, 580> *return$) noexcept;

::rust::repr::PtrLen sapling$cxxbridge1$UnauthorizedBundle$output_out_ciphertext(::sapling::UnauthorizedBundle const &self, ::std::size_t i, ::std::array<::std::uint8_t, 80> *return$) noexcept;

::rust::repr::PtrLen sapling$cxxbridge1$UnauthorizedBundle$output_zkproof(::sapling::UnauthorizedBundle const &self, ::std::size_t i, ::std::array<::std::uint8_t, 192> *return$) noexcept;

::rust::repr::PtrLen sapling$cxxbridge1$apply_sapling_bundle_signatures(::sapling::UnauthorizedBundle *bundle, ::std::array<::std::uint8_t, 32> *sighash_bytes, ::rust::Box<::sapling::Bundle> *return$) noexcept;
::std::size_t sapling$cxxbridge1$Verifier$operator$sizeof() noexcept;
::std::size_t sapling$cxxbridge1$Verifier$operator$alignof() noexcept;

::sapling::Verifier *sapling$cxxbridge1$init_verifier() noexcept;

bool sapling$cxxbridge1$Verifier$check_spend(::sapling::Verifier &self, ::std::array<::std::uint8_t, 32> const &cv, ::std::array<::std::uint8_t, 32> const &anchor, ::std::array<::std::uint8_t, 32> const &nullifier, ::std::array<::std::uint8_t, 32> const &rk, ::std::array<::std::uint8_t, 192> const &zkproof, ::std::array<::std::uint8_t, 64> const &spend_auth_sig, ::std::array<::std::uint8_t, 32> const &sighash_value) noexcept;

bool sapling$cxxbridge1$Verifier$check_output(::sapling::Verifier &self, ::std::array<::std::uint8_t, 32> const &cv, ::std::array<::std::uint8_t, 32> const &cm, ::std::array<::std::uint8_t, 32> const &ephemeral_key, ::std::array<::std::uint8_t, 192> const &zkproof) noexcept;

bool sapling$cxxbridge1$Verifier$final_check(::sapling::Verifier const &self, ::std::int64_t value_balance, ::std::array<::std::uint8_t, 64> const &binding_sig, ::std::array<::std::uint8_t, 32> const &sighash_value) noexcept;
::std::size_t sapling$cxxbridge1$BatchValidator$operator$sizeof() noexcept;
::std::size_t sapling$cxxbridge1$BatchValidator$operator$alignof() noexcept;

::sapling::BatchValidator *sapling$cxxbridge1$init_sapling_batch_validator(bool cache_store) noexcept;

bool sapling$cxxbridge1$BatchValidator$check_bundle(::sapling::BatchValidator &self, ::sapling::Bundle *bundle, ::std::array<::std::uint8_t, 32> *sighash) noexcept;

bool sapling$cxxbridge1$BatchValidator$validate(::sapling::BatchValidator &self) noexcept;
} // extern "C"

namespace zip32 {
extern "C" {
::rust::repr::PtrLen sapling$zip32$cxxbridge1$xsk_master(::rust::Slice<::std::uint8_t const> seed, ::std::array<::std::uint8_t, 169> *return$) noexcept;

::rust::repr::PtrLen sapling$zip32$cxxbridge1$xsk_derive(::std::array<::std::uint8_t, 169> const &xsk_parent, ::std::uint32_t i, ::std::array<::std::uint8_t, 169> *return$) noexcept;

::rust::repr::PtrLen sapling$zip32$cxxbridge1$xsk_derive_internal(::std::array<::std::uint8_t, 169> const &xsk_external, ::std::array<::std::uint8_t, 169> *return$) noexcept;

::rust::repr::PtrLen sapling$zip32$cxxbridge1$xsk_to_fvk(::std::array<::std::uint8_t, 169> const &xsk, ::std::array<::std::uint8_t, 96> *return$) noexcept;

::rust::repr::PtrLen sapling$zip32$cxxbridge1$xsk_to_dk(::std::array<::std::uint8_t, 169> const &xsk, ::std::array<::std::uint8_t, 32> *return$) noexcept;

::rust::repr::PtrLen sapling$zip32$cxxbridge1$xsk_to_ivk(::std::array<::std::uint8_t, 169> const &xsk, ::std::array<::std::uint8_t, 32> *return$) noexcept;

::rust::repr::PtrLen sapling$zip32$cxxbridge1$xsk_to_default_address(::std::array<::std::uint8_t, 169> const &xsk, ::std::array<::std::uint8_t, 43> *return$) noexcept;

::rust::repr::PtrLen sapling$zip32$cxxbridge1$derive_internal_fvk(::std::array<::std::uint8_t, 96> const &fvk, ::std::array<::std::uint8_t, 32> *dk, ::sapling::zip32::Zip32Fvk *return$) noexcept;

::rust::repr::PtrLen sapling$zip32$cxxbridge1$zip32_address(::std::array<::std::uint8_t, 96> const &fvk, ::std::array<::std::uint8_t, 32> *dk, ::std::array<::std::uint8_t, 11> *j, ::std::array<::std::uint8_t, 43> *return$) noexcept;

::rust::repr::PtrLen sapling$zip32$cxxbridge1$zip32_find_address(::std::array<::std::uint8_t, 96> const &fvk, ::std::array<::std::uint8_t, 32> *dk, ::std::array<::std::uint8_t, 11> *j, ::sapling::zip32::Zip32Address *return$) noexcept;

void sapling$zip32$cxxbridge1$diversifier_index(::std::array<::std::uint8_t, 32> *dk, ::std::array<::std::uint8_t, 11> *d, ::std::array<::std::uint8_t, 11> *return$) noexcept;

::rust::repr::PtrLen sapling$zip32$cxxbridge1$fvk_to_ivk(::std::array<::std::uint8_t, 96> const &fvk, ::std::array<::std::uint8_t, 32> *return$) noexcept;

::rust::repr::PtrLen sapling$zip32$cxxbridge1$fvk_default_address(::std::array<::std::uint8_t, 96> const &fvk, ::std::array<::std::uint8_t, 32> *dk, ::std::array<::std::uint8_t, 43> *return$) noexcept;
} // extern "C"
} // namespace zip32
} // namespace sapling

namespace wallet {
extern "C" {
::rust::repr::PtrLen wallet$cxxbridge1$try_sapling_note_decryption(::consensus::Network const &network, ::std::uint32_t height, ::std::array<::std::uint8_t, 32> const &raw_ivk, ::wallet::SaplingShieldedOutput output, ::rust::Box<::wallet::DecryptedSaplingOutput> *return$) noexcept;

::rust::repr::PtrLen wallet$cxxbridge1$try_sapling_output_recovery(::consensus::Network const &network, ::std::uint32_t height, ::std::array<::std::uint8_t, 32> *ovk, ::wallet::SaplingShieldedOutput output, ::rust::Box<::wallet::DecryptedSaplingOutput> *return$) noexcept;
::std::size_t wallet$cxxbridge1$DecryptedSaplingOutput$operator$sizeof() noexcept;
::std::size_t wallet$cxxbridge1$DecryptedSaplingOutput$operator$alignof() noexcept;

::std::uint64_t wallet$cxxbridge1$DecryptedSaplingOutput$note_value(::wallet::DecryptedSaplingOutput const &self) noexcept;

void wallet$cxxbridge1$DecryptedSaplingOutput$note_rseed(::wallet::DecryptedSaplingOutput const &self, ::std::array<::std::uint8_t, 32> *return$) noexcept;

bool wallet$cxxbridge1$DecryptedSaplingOutput$zip_212_enabled(::wallet::DecryptedSaplingOutput const &self) noexcept;

void wallet$cxxbridge1$DecryptedSaplingOutput$recipient_d(::wallet::DecryptedSaplingOutput const &self, ::std::array<::std::uint8_t, 11> *return$) noexcept;

void wallet$cxxbridge1$DecryptedSaplingOutput$recipient_pk_d(::wallet::DecryptedSaplingOutput const &self, ::std::array<::std::uint8_t, 32> *return$) noexcept;

void wallet$cxxbridge1$DecryptedSaplingOutput$memo(::wallet::DecryptedSaplingOutput const &self, ::std::array<::std::uint8_t, 512> *return$) noexcept;
} // extern "C"
} // namespace wallet

namespace sapling {
namespace tree {
extern "C" {
::std::size_t sapling$tree$cxxbridge1$SaplingFrontier$operator$sizeof() noexcept;
::std::size_t sapling$tree$cxxbridge1$SaplingFrontier$operator$alignof() noexcept;

::sapling::tree::SaplingFrontier *sapling$tree$cxxbridge1$new_sapling_frontier() noexcept;

::rust::repr::PtrLen sapling$tree$cxxbridge1$frontier_append(::sapling::tree::SaplingFrontier &tree, ::std::array<::std::uint8_t, 32> const &cmu) noexcept;

void sapling$tree$cxxbridge1$frontier_root(::sapling::tree::SaplingFrontier const &tree, ::std::array<::std::uint8_t, 32> *return$) noexcept;

::std::uint64_t sapling$tree$cxxbridge1$frontier_size(::sapling::tree::SaplingFrontier const &tree) noexcept;

void sapling$tree$cxxbridge1$frontier_serialize(::sapling::tree::SaplingFrontier const &tree, ::rust::Vec<::std::uint8_t> *return$) noexcept;

::rust::repr::PtrLen sapling$tree$cxxbridge1$frontier_deserialize(::rust::Slice<::std::uint8_t const> data, ::rust::Box<::sapling::tree::SaplingFrontier> *return$) noexcept;
::std::size_t sapling$tree$cxxbridge1$SaplingWitness$operator$sizeof() noexcept;
::std::size_t sapling$tree$cxxbridge1$SaplingWitness$operator$alignof() noexcept;

::rust::repr::PtrLen sapling$tree$cxxbridge1$witness_from_frontier(::sapling::tree::SaplingFrontier const &tree, ::rust::Box<::sapling::tree::SaplingWitness> *return$) noexcept;

::rust::repr::PtrLen sapling$tree$cxxbridge1$witness_append(::sapling::tree::SaplingWitness &wit, ::std::array<::std::uint8_t, 32> const &cmu) noexcept;

void sapling$tree$cxxbridge1$witness_root(::sapling::tree::SaplingWitness const &wit, ::std::array<::std::uint8_t, 32> *return$) noexcept;

::std::uint64_t sapling$tree$cxxbridge1$witness_position(::sapling::tree::SaplingWitness const &wit) noexcept;

::rust::repr::PtrLen sapling$tree$cxxbridge1$witness_path(::sapling::tree::SaplingWitness const &wit, ::std::array<::std::uint8_t, 1065> *return$) noexcept;

void sapling$tree$cxxbridge1$witness_serialize(::sapling::tree::SaplingWitness const &wit, ::rust::Vec<::std::uint8_t> *return$) noexcept;

::rust::repr::PtrLen sapling$tree$cxxbridge1$witness_deserialize(::rust::Slice<::std::uint8_t const> data, ::rust::Box<::sapling::tree::SaplingWitness> *return$) noexcept;
} // extern "C"
} // namespace tree

extern "C" {
::rust::repr::PtrLen sapling$cxxbridge1$init_sapling_params(::rust::Str spend_path, ::rust::Str output_path) noexcept;

bool sapling$cxxbridge1$is_sapling_initialized() noexcept;
} // extern "C"
} // namespace sapling

namespace hmp {
extern "C" {
::rust::repr::PtrLen hmp$cxxbridge1$init_hmp_params() noexcept;

bool hmp$cxxbridge1$is_hmp_initialized() noexcept;

::rust::repr::PtrLen hmp$cxxbridge1$hmp_create_proof(::std::array<::std::uint8_t, 32> const &sk_bytes, ::std::array<::std::uint8_t, 32> const &block_hash, ::std::array<::std::uint8_t, 32> const &chain_state_hash, ::rust::Vec<::std::uint8_t> *return$) noexcept;

::rust::repr::PtrLen hmp$cxxbridge1$hmp_verify_proof(::rust::Slice<::std::uint8_t const> proof_bytes, ::std::array<::std::uint8_t, 32> const &block_hash, ::std::array<::std::uint8_t, 32> const &commitment, bool *return$) noexcept;

::rust::repr::PtrLen hmp$cxxbridge1$hmp_compute_commitment(::std::array<::std::uint8_t, 32> const &sk_bytes, ::std::array<::std::uint8_t, 32> const &block_hash, ::std::array<::std::uint8_t, 32> const &chain_state_hash, ::std::array<::std::uint8_t, 32> *return$) noexcept;
} // extern "C"
} // namespace hmp

namespace stream {
::std::size_t CppStream::layout::size() noexcept {
  return stream$cxxbridge1$CppStream$operator$sizeof();
}

::std::size_t CppStream::layout::align() noexcept {
  return stream$cxxbridge1$CppStream$operator$alignof();
}

::rust::Box<::stream::CppStream> from_data(::RustDataStream &stream) noexcept {
  return ::rust::Box<::stream::CppStream>::from_raw(stream$cxxbridge1$from_data(stream));
}

::rust::Box<::stream::CppStream> from_auto_file(::CAutoFile &file) noexcept {
  return ::rust::Box<::stream::CppStream>::from_raw(stream$cxxbridge1$from_auto_file(file));
}

::rust::Box<::stream::CppStream> from_buffered_file(::CBufferedFile &file) noexcept {
  return ::rust::Box<::stream::CppStream>::from_raw(stream$cxxbridge1$from_buffered_file(file));
}

::rust::Box<::stream::CppStream> from_hash_writer(::CHashWriter &writer) noexcept {
  return ::rust::Box<::stream::CppStream>::from_raw(stream$cxxbridge1$from_hash_writer(writer));
}

::rust::Box<::stream::CppStream> from_size_computer(::CSizeComputer &sc) noexcept {
  return ::rust::Box<::stream::CppStream>::from_raw(stream$cxxbridge1$from_size_computer(sc));
}
} // namespace stream

namespace consensus {
::std::size_t Network::layout::size() noexcept {
  return consensus$cxxbridge1$Network$operator$sizeof();
}

::std::size_t Network::layout::align() noexcept {
  return consensus$cxxbridge1$Network$operator$alignof();
}

::rust::Box<::consensus::Network> network(::rust::Str network, ::std::int32_t overwinter, ::std::int32_t sapling, ::std::int32_t blossom, ::std::int32_t heartwood, ::std::int32_t canopy, ::std::int32_t nu5, ::std::int32_t nu6, ::std::int32_t nu6_1) {
  ::rust::MaybeUninit<::rust::Box<::consensus::Network>> return$;
  ::rust::repr::PtrLen error$ = consensus$cxxbridge1$network(network, overwinter, sapling, blossom, heartwood, canopy, nu5, nu6, nu6_1, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}
} // namespace consensus

namespace bundlecache {
void init(::std::size_t cache_bytes) noexcept {
  bundlecache$cxxbridge1$bundlecache_init(cache_bytes);
}
} // namespace bundlecache

namespace sapling {
::std::size_t Spend::layout::size() noexcept {
  return sapling$cxxbridge1$Spend$operator$sizeof();
}

::std::size_t Spend::layout::align() noexcept {
  return sapling$cxxbridge1$Spend$operator$alignof();
}

::rust::Box<::sapling::Spend> parse_v4_spend(::rust::Slice<::std::uint8_t const> bytes) {
  ::rust::MaybeUninit<::rust::Box<::sapling::Spend>> return$;
  ::rust::repr::PtrLen error$ = sapling$cxxbridge1$parse_v4_sapling_spend(bytes, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 32> Spend::cv() const noexcept {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  sapling$cxxbridge1$Spend$cv(*this, &return$.value);
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 32> Spend::anchor() const noexcept {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  sapling$cxxbridge1$Spend$anchor(*this, &return$.value);
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 32> Spend::nullifier() const noexcept {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  sapling$cxxbridge1$Spend$nullifier(*this, &return$.value);
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 32> Spend::rk() const noexcept {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  sapling$cxxbridge1$Spend$rk(*this, &return$.value);
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 192> Spend::zkproof() const noexcept {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 192>> return$;
  sapling$cxxbridge1$Spend$zkproof(*this, &return$.value);
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 64> Spend::spend_auth_sig() const noexcept {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 64>> return$;
  sapling$cxxbridge1$Spend$spend_auth_sig(*this, &return$.value);
  return ::std::move(return$.value);
}

::std::size_t Output::layout::size() noexcept {
  return sapling$cxxbridge1$Output$operator$sizeof();
}

::std::size_t Output::layout::align() noexcept {
  return sapling$cxxbridge1$Output$operator$alignof();
}

::rust::Box<::sapling::Output> parse_v4_output(::rust::Slice<::std::uint8_t const> bytes) {
  ::rust::MaybeUninit<::rust::Box<::sapling::Output>> return$;
  ::rust::repr::PtrLen error$ = sapling$cxxbridge1$parse_v4_sapling_output(bytes, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 32> Output::cv() const noexcept {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  sapling$cxxbridge1$Output$cv(*this, &return$.value);
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 32> Output::cmu() const noexcept {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  sapling$cxxbridge1$Output$cmu(*this, &return$.value);
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 32> Output::ephemeral_key() const noexcept {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  sapling$cxxbridge1$Output$ephemeral_key(*this, &return$.value);
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 580> Output::enc_ciphertext() const noexcept {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 580>> return$;
  sapling$cxxbridge1$Output$enc_ciphertext(*this, &return$.value);
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 80> Output::out_ciphertext() const noexcept {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 80>> return$;
  sapling$cxxbridge1$Output$out_ciphertext(*this, &return$.value);
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 192> Output::zkproof() const noexcept {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 192>> return$;
  sapling$cxxbridge1$Output$zkproof(*this, &return$.value);
  return ::std::move(return$.value);
}

void Output::serialize_v4(::stream::CppStream &stream) const {
  ::rust::repr::PtrLen error$ = sapling$cxxbridge1$Output$serialize_v4(*this, stream);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
}

::std::size_t Bundle::layout::size() noexcept {
  return sapling$cxxbridge1$Bundle$operator$sizeof();
}

::std::size_t Bundle::layout::align() noexcept {
  return sapling$cxxbridge1$Bundle$operator$alignof();
}

::rust::Box<::sapling::Bundle> none_bundle() noexcept {
  return ::rust::Box<::sapling::Bundle>::from_raw(sapling$cxxbridge1$none_sapling_bundle());
}

::rust::Box<::sapling::Bundle> Bundle::box_clone() const noexcept {
  return ::rust::Box<::sapling::Bundle>::from_raw(sapling$cxxbridge1$Bundle$box_clone(*this));
}

::rust::Box<::sapling::Bundle> parse_v5_bundle(::stream::CppStream &stream) {
  ::rust::MaybeUninit<::rust::Box<::sapling::Bundle>> return$;
  ::rust::repr::PtrLen error$ = sapling$cxxbridge1$parse_v5_sapling_bundle(stream, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

void Bundle::serialize_v4_components(::stream::CppStream &stream, bool has_sapling) const {
  ::rust::repr::PtrLen error$ = sapling$cxxbridge1$Bundle$serialize_v4_components(*this, stream, has_sapling);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
}

void Bundle::serialize_v5(::stream::CppStream &stream) const {
  ::rust::repr::PtrLen error$ = sapling$cxxbridge1$Bundle$serialize_v5(*this, stream);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
}

::std::size_t Bundle::recursive_dynamic_usage() const noexcept {
  return sapling$cxxbridge1$Bundle$recursive_dynamic_usage(*this);
}

bool Bundle::is_present() const noexcept {
  return sapling$cxxbridge1$Bundle$is_present(*this);
}

::rust::Vec<::sapling::Spend> Bundle::spends() const noexcept {
  ::rust::MaybeUninit<::rust::Vec<::sapling::Spend>> return$;
  sapling$cxxbridge1$Bundle$spends(*this, &return$.value);
  return ::std::move(return$.value);
}

::rust::Vec<::sapling::Output> Bundle::outputs() const noexcept {
  ::rust::MaybeUninit<::rust::Vec<::sapling::Output>> return$;
  sapling$cxxbridge1$Bundle$outputs(*this, &return$.value);
  return ::std::move(return$.value);
}

::std::size_t Bundle::num_spends() const noexcept {
  return sapling$cxxbridge1$Bundle$num_spends(*this);
}

::std::size_t Bundle::num_outputs() const noexcept {
  return sapling$cxxbridge1$Bundle$num_outputs(*this);
}

::std::int64_t Bundle::value_balance_zat() const noexcept {
  return sapling$cxxbridge1$Bundle$value_balance_zat(*this);
}

::std::array<::std::uint8_t, 64> Bundle::binding_sig() const {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 64>> return$;
  ::rust::repr::PtrLen error$ = sapling$cxxbridge1$Bundle$binding_sig(*this, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

::std::size_t BundleAssembler::layout::size() noexcept {
  return sapling$cxxbridge1$BundleAssembler$operator$sizeof();
}

::std::size_t BundleAssembler::layout::align() noexcept {
  return sapling$cxxbridge1$BundleAssembler$operator$alignof();
}

::rust::Box<::sapling::BundleAssembler> new_bundle_assembler() noexcept {
  return ::rust::Box<::sapling::BundleAssembler>::from_raw(sapling$cxxbridge1$new_bundle_assembler());
}

::rust::Box<::sapling::BundleAssembler> parse_v4_components(::stream::CppStream &stream, bool has_sapling) {
  ::rust::MaybeUninit<::rust::Box<::sapling::BundleAssembler>> return$;
  ::rust::repr::PtrLen error$ = sapling$cxxbridge1$parse_v4_sapling_components(stream, has_sapling, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

bool BundleAssembler::have_actions() const noexcept {
  return sapling$cxxbridge1$BundleAssembler$have_actions(*this);
}

::rust::Box<::sapling::Bundle> finish_bundle_assembly(::rust::Box<::sapling::BundleAssembler> assembler, ::std::array<::std::uint8_t, 64> binding_sig) noexcept {
  ::rust::ManuallyDrop<::std::array<::std::uint8_t, 64>> binding_sig$(::std::move(binding_sig));
  return ::rust::Box<::sapling::Bundle>::from_raw(sapling$cxxbridge1$finish_bundle_assembly(assembler.into_raw(), &binding_sig$.value));
}

::std::size_t Builder::layout::size() noexcept {
  return sapling$cxxbridge1$Builder$operator$sizeof();
}

::std::size_t Builder::layout::align() noexcept {
  return sapling$cxxbridge1$Builder$operator$alignof();
}

::rust::Box<::sapling::Builder> new_builder(::consensus::Network const &network, ::std::uint32_t height, ::std::array<::std::uint8_t, 32> anchor, bool coinbase) {
  ::rust::ManuallyDrop<::std::array<::std::uint8_t, 32>> anchor$(::std::move(anchor));
  ::rust::MaybeUninit<::rust::Box<::sapling::Builder>> return$;
  ::rust::repr::PtrLen error$ = sapling$cxxbridge1$new_sapling_builder(network, height, &anchor$.value, coinbase, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

void Builder::add_spend(::rust::Slice<::std::uint8_t const> extsk, ::std::array<::std::uint8_t, 43> recipient, ::std::uint64_t value, ::std::array<::std::uint8_t, 32> rcm, ::std::array<::std::uint8_t, 1065> merkle_path) {
  ::rust::ManuallyDrop<::std::array<::std::uint8_t, 43>> recipient$(::std::move(recipient));
  ::rust::ManuallyDrop<::std::array<::std::uint8_t, 32>> rcm$(::std::move(rcm));
  ::rust::ManuallyDrop<::std::array<::std::uint8_t, 1065>> merkle_path$(::std::move(merkle_path));
  ::rust::repr::PtrLen error$ = sapling$cxxbridge1$Builder$add_spend(*this, extsk, &recipient$.value, value, &rcm$.value, &merkle_path$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
}

void Builder::add_recipient(::std::array<::std::uint8_t, 32> ovk, ::std::array<::std::uint8_t, 43> to, ::std::uint64_t value, ::std::array<::std::uint8_t, 512> memo) {
  ::rust::ManuallyDrop<::std::array<::std::uint8_t, 32>> ovk$(::std::move(ovk));
  ::rust::ManuallyDrop<::std::array<::std::uint8_t, 43>> to$(::std::move(to));
  ::rust::ManuallyDrop<::std::array<::std::uint8_t, 512>> memo$(::std::move(memo));
  ::rust::repr::PtrLen error$ = sapling$cxxbridge1$Builder$add_recipient(*this, &ovk$.value, &to$.value, value, &memo$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
}

void Builder::add_recipient_no_ovk(::std::array<::std::uint8_t, 43> to, ::std::uint64_t value, ::std::array<::std::uint8_t, 512> memo) {
  ::rust::ManuallyDrop<::std::array<::std::uint8_t, 43>> to$(::std::move(to));
  ::rust::ManuallyDrop<::std::array<::std::uint8_t, 512>> memo$(::std::move(memo));
  ::rust::repr::PtrLen error$ = sapling$cxxbridge1$Builder$add_recipient_no_ovk(*this, &to$.value, value, &memo$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
}

::rust::Box<::sapling::UnauthorizedBundle> build_bundle(::rust::Box<::sapling::Builder> builder) {
  ::rust::MaybeUninit<::rust::Box<::sapling::UnauthorizedBundle>> return$;
  ::rust::repr::PtrLen error$ = sapling$cxxbridge1$build_sapling_bundle(builder.into_raw(), &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

::std::size_t UnauthorizedBundle::layout::size() noexcept {
  return sapling$cxxbridge1$UnauthorizedBundle$operator$sizeof();
}

::std::size_t UnauthorizedBundle::layout::align() noexcept {
  return sapling$cxxbridge1$UnauthorizedBundle$operator$alignof();
}

::std::size_t UnauthorizedBundle::num_spends() const noexcept {
  return sapling$cxxbridge1$UnauthorizedBundle$num_spends(*this);
}

::std::size_t UnauthorizedBundle::num_outputs() const noexcept {
  return sapling$cxxbridge1$UnauthorizedBundle$num_outputs(*this);
}

::std::int64_t UnauthorizedBundle::value_balance_zat() const noexcept {
  return sapling$cxxbridge1$UnauthorizedBundle$value_balance_zat(*this);
}

::std::array<::std::uint8_t, 32> UnauthorizedBundle::spend_cv(::std::size_t i) const {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  ::rust::repr::PtrLen error$ = sapling$cxxbridge1$UnauthorizedBundle$spend_cv(*this, i, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 32> UnauthorizedBundle::spend_anchor(::std::size_t i) const {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  ::rust::repr::PtrLen error$ = sapling$cxxbridge1$UnauthorizedBundle$spend_anchor(*this, i, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 32> UnauthorizedBundle::spend_nullifier(::std::size_t i) const {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  ::rust::repr::PtrLen error$ = sapling$cxxbridge1$UnauthorizedBundle$spend_nullifier(*this, i, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 32> UnauthorizedBundle::spend_rk(::std::size_t i) const {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  ::rust::repr::PtrLen error$ = sapling$cxxbridge1$UnauthorizedBundle$spend_rk(*this, i, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 192> UnauthorizedBundle::spend_zkproof(::std::size_t i) const {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 192>> return$;
  ::rust::repr::PtrLen error$ = sapling$cxxbridge1$UnauthorizedBundle$spend_zkproof(*this, i, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 32> UnauthorizedBundle::output_cv(::std::size_t i) const {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  ::rust::repr::PtrLen error$ = sapling$cxxbridge1$UnauthorizedBundle$output_cv(*this, i, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 32> UnauthorizedBundle::output_cmu(::std::size_t i) const {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  ::rust::repr::PtrLen error$ = sapling$cxxbridge1$UnauthorizedBundle$output_cmu(*this, i, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 32> UnauthorizedBundle::output_ephemeral_key(::std::size_t i) const {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  ::rust::repr::PtrLen error$ = sapling$cxxbridge1$UnauthorizedBundle$output_ephemeral_key(*this, i, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 580> UnauthorizedBundle::output_enc_ciphertext(::std::size_t i) const {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 580>> return$;
  ::rust::repr::PtrLen error$ = sapling$cxxbridge1$UnauthorizedBundle$output_enc_ciphertext(*this, i, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 80> UnauthorizedBundle::output_out_ciphertext(::std::size_t i) const {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 80>> return$;
  ::rust::repr::PtrLen error$ = sapling$cxxbridge1$UnauthorizedBundle$output_out_ciphertext(*this, i, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 192> UnauthorizedBundle::output_zkproof(::std::size_t i) const {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 192>> return$;
  ::rust::repr::PtrLen error$ = sapling$cxxbridge1$UnauthorizedBundle$output_zkproof(*this, i, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

::rust::Box<::sapling::Bundle> apply_bundle_signatures(::rust::Box<::sapling::UnauthorizedBundle> bundle, ::std::array<::std::uint8_t, 32> sighash_bytes) {
  ::rust::ManuallyDrop<::std::array<::std::uint8_t, 32>> sighash_bytes$(::std::move(sighash_bytes));
  ::rust::MaybeUninit<::rust::Box<::sapling::Bundle>> return$;
  ::rust::repr::PtrLen error$ = sapling$cxxbridge1$apply_sapling_bundle_signatures(bundle.into_raw(), &sighash_bytes$.value, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

::std::size_t Verifier::layout::size() noexcept {
  return sapling$cxxbridge1$Verifier$operator$sizeof();
}

::std::size_t Verifier::layout::align() noexcept {
  return sapling$cxxbridge1$Verifier$operator$alignof();
}

::rust::Box<::sapling::Verifier> init_verifier() noexcept {
  return ::rust::Box<::sapling::Verifier>::from_raw(sapling$cxxbridge1$init_verifier());
}

bool Verifier::check_spend(::std::array<::std::uint8_t, 32> const &cv, ::std::array<::std::uint8_t, 32> const &anchor, ::std::array<::std::uint8_t, 32> const &nullifier, ::std::array<::std::uint8_t, 32> const &rk, ::std::array<::std::uint8_t, 192> const &zkproof, ::std::array<::std::uint8_t, 64> const &spend_auth_sig, ::std::array<::std::uint8_t, 32> const &sighash_value) noexcept {
  return sapling$cxxbridge1$Verifier$check_spend(*this, cv, anchor, nullifier, rk, zkproof, spend_auth_sig, sighash_value);
}

bool Verifier::check_output(::std::array<::std::uint8_t, 32> const &cv, ::std::array<::std::uint8_t, 32> const &cm, ::std::array<::std::uint8_t, 32> const &ephemeral_key, ::std::array<::std::uint8_t, 192> const &zkproof) noexcept {
  return sapling$cxxbridge1$Verifier$check_output(*this, cv, cm, ephemeral_key, zkproof);
}

bool Verifier::final_check(::std::int64_t value_balance, ::std::array<::std::uint8_t, 64> const &binding_sig, ::std::array<::std::uint8_t, 32> const &sighash_value) const noexcept {
  return sapling$cxxbridge1$Verifier$final_check(*this, value_balance, binding_sig, sighash_value);
}

::std::size_t BatchValidator::layout::size() noexcept {
  return sapling$cxxbridge1$BatchValidator$operator$sizeof();
}

::std::size_t BatchValidator::layout::align() noexcept {
  return sapling$cxxbridge1$BatchValidator$operator$alignof();
}

::rust::Box<::sapling::BatchValidator> init_batch_validator(bool cache_store) noexcept {
  return ::rust::Box<::sapling::BatchValidator>::from_raw(sapling$cxxbridge1$init_sapling_batch_validator(cache_store));
}

bool BatchValidator::check_bundle(::rust::Box<::sapling::Bundle> bundle, ::std::array<::std::uint8_t, 32> sighash) noexcept {
  ::rust::ManuallyDrop<::std::array<::std::uint8_t, 32>> sighash$(::std::move(sighash));
  return sapling$cxxbridge1$BatchValidator$check_bundle(*this, bundle.into_raw(), &sighash$.value);
}

bool BatchValidator::validate() noexcept {
  return sapling$cxxbridge1$BatchValidator$validate(*this);
}

namespace zip32 {
// Derive master ExtendedSpendingKey from seed bytes.
::std::array<::std::uint8_t, 169> xsk_master(::rust::Slice<::std::uint8_t const> seed) {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 169>> return$;
  ::rust::repr::PtrLen error$ = sapling$zip32$cxxbridge1$xsk_master(seed, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

// Derive child ExtendedSpendingKey from parent.
::std::array<::std::uint8_t, 169> xsk_derive(::std::array<::std::uint8_t, 169> const &xsk_parent, ::std::uint32_t i) {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 169>> return$;
  ::rust::repr::PtrLen error$ = sapling$zip32$cxxbridge1$xsk_derive(xsk_parent, i, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

// Derive the internal (change) ExtSK from an external ExtSK.
::std::array<::std::uint8_t, 169> xsk_derive_internal(::std::array<::std::uint8_t, 169> const &xsk_external) {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 169>> return$;
  ::rust::repr::PtrLen error$ = sapling$zip32$cxxbridge1$xsk_derive_internal(xsk_external, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

// Extract the 96-byte FullViewingKey (ak || nk || ovk) from an ExtSK.
::std::array<::std::uint8_t, 96> xsk_to_fvk(::std::array<::std::uint8_t, 169> const &xsk) {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 96>> return$;
  ::rust::repr::PtrLen error$ = sapling$zip32$cxxbridge1$xsk_to_fvk(xsk, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

// Extract the 32-byte DiversifierKey from an ExtSK.
::std::array<::std::uint8_t, 32> xsk_to_dk(::std::array<::std::uint8_t, 169> const &xsk) {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  ::rust::repr::PtrLen error$ = sapling$zip32$cxxbridge1$xsk_to_dk(xsk, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

// Extract the 32-byte IncomingViewingKey from an ExtSK.
::std::array<::std::uint8_t, 32> xsk_to_ivk(::std::array<::std::uint8_t, 169> const &xsk) {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  ::rust::repr::PtrLen error$ = sapling$zip32$cxxbridge1$xsk_to_ivk(xsk, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

// Derive the default payment address (43 bytes) from an ExtSK.
::std::array<::std::uint8_t, 43> xsk_to_default_address(::std::array<::std::uint8_t, 169> const &xsk) {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 43>> return$;
  ::rust::repr::PtrLen error$ = sapling$zip32$cxxbridge1$xsk_to_default_address(xsk, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

// Derive the internal FVK + DK from a FVK + DK.
::sapling::zip32::Zip32Fvk derive_internal_fvk(::std::array<::std::uint8_t, 96> const &fvk, ::std::array<::std::uint8_t, 32> dk) {
  ::rust::ManuallyDrop<::std::array<::std::uint8_t, 32>> dk$(::std::move(dk));
  ::rust::MaybeUninit<::sapling::zip32::Zip32Fvk> return$;
  ::rust::repr::PtrLen error$ = sapling$zip32$cxxbridge1$derive_internal_fvk(fvk, &dk$.value, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

// Derive a payment address at diversifier index j.
::std::array<::std::uint8_t, 43> address(::std::array<::std::uint8_t, 96> const &fvk, ::std::array<::std::uint8_t, 32> dk, ::std::array<::std::uint8_t, 11> j) {
  ::rust::ManuallyDrop<::std::array<::std::uint8_t, 32>> dk$(::std::move(dk));
  ::rust::ManuallyDrop<::std::array<::std::uint8_t, 11>> j$(::std::move(j));
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 43>> return$;
  ::rust::repr::PtrLen error$ = sapling$zip32$cxxbridge1$zip32_address(fvk, &dk$.value, &j$.value, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

// Find the next valid diversified address at or above index j.
::sapling::zip32::Zip32Address find_address(::std::array<::std::uint8_t, 96> const &fvk, ::std::array<::std::uint8_t, 32> dk, ::std::array<::std::uint8_t, 11> j) {
  ::rust::ManuallyDrop<::std::array<::std::uint8_t, 32>> dk$(::std::move(dk));
  ::rust::ManuallyDrop<::std::array<::std::uint8_t, 11>> j$(::std::move(j));
  ::rust::MaybeUninit<::sapling::zip32::Zip32Address> return$;
  ::rust::repr::PtrLen error$ = sapling$zip32$cxxbridge1$zip32_find_address(fvk, &dk$.value, &j$.value, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

// Get the diversifier index for a given diversifier.
::std::array<::std::uint8_t, 11> diversifier_index(::std::array<::std::uint8_t, 32> dk, ::std::array<::std::uint8_t, 11> d) noexcept {
  ::rust::ManuallyDrop<::std::array<::std::uint8_t, 32>> dk$(::std::move(dk));
  ::rust::ManuallyDrop<::std::array<::std::uint8_t, 11>> d$(::std::move(d));
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 11>> return$;
  sapling$zip32$cxxbridge1$diversifier_index(&dk$.value, &d$.value, &return$.value);
  return ::std::move(return$.value);
}

// Derive IVK from a 96-byte FVK.
::std::array<::std::uint8_t, 32> fvk_to_ivk(::std::array<::std::uint8_t, 96> const &fvk) {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  ::rust::repr::PtrLen error$ = sapling$zip32$cxxbridge1$fvk_to_ivk(fvk, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

// Derive the default payment address from a FVK + DK.
::std::array<::std::uint8_t, 43> fvk_default_address(::std::array<::std::uint8_t, 96> const &fvk, ::std::array<::std::uint8_t, 32> dk) {
  ::rust::ManuallyDrop<::std::array<::std::uint8_t, 32>> dk$(::std::move(dk));
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 43>> return$;
  ::rust::repr::PtrLen error$ = sapling$zip32$cxxbridge1$fvk_default_address(fvk, &dk$.value, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}
} // namespace zip32
} // namespace sapling

namespace wallet {
::rust::Box<::wallet::DecryptedSaplingOutput> try_sapling_note_decryption(::consensus::Network const &network, ::std::uint32_t height, ::std::array<::std::uint8_t, 32> const &raw_ivk, ::wallet::SaplingShieldedOutput output) {
  ::rust::MaybeUninit<::rust::Box<::wallet::DecryptedSaplingOutput>> return$;
  ::rust::repr::PtrLen error$ = wallet$cxxbridge1$try_sapling_note_decryption(network, height, raw_ivk, output, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

::rust::Box<::wallet::DecryptedSaplingOutput> try_sapling_output_recovery(::consensus::Network const &network, ::std::uint32_t height, ::std::array<::std::uint8_t, 32> ovk, ::wallet::SaplingShieldedOutput output) {
  ::rust::ManuallyDrop<::std::array<::std::uint8_t, 32>> ovk$(::std::move(ovk));
  ::rust::MaybeUninit<::rust::Box<::wallet::DecryptedSaplingOutput>> return$;
  ::rust::repr::PtrLen error$ = wallet$cxxbridge1$try_sapling_output_recovery(network, height, &ovk$.value, output, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

::std::size_t DecryptedSaplingOutput::layout::size() noexcept {
  return wallet$cxxbridge1$DecryptedSaplingOutput$operator$sizeof();
}

::std::size_t DecryptedSaplingOutput::layout::align() noexcept {
  return wallet$cxxbridge1$DecryptedSaplingOutput$operator$alignof();
}

::std::uint64_t DecryptedSaplingOutput::note_value() const noexcept {
  return wallet$cxxbridge1$DecryptedSaplingOutput$note_value(*this);
}

::std::array<::std::uint8_t, 32> DecryptedSaplingOutput::note_rseed() const noexcept {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  wallet$cxxbridge1$DecryptedSaplingOutput$note_rseed(*this, &return$.value);
  return ::std::move(return$.value);
}

bool DecryptedSaplingOutput::zip_212_enabled() const noexcept {
  return wallet$cxxbridge1$DecryptedSaplingOutput$zip_212_enabled(*this);
}

::std::array<::std::uint8_t, 11> DecryptedSaplingOutput::recipient_d() const noexcept {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 11>> return$;
  wallet$cxxbridge1$DecryptedSaplingOutput$recipient_d(*this, &return$.value);
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 32> DecryptedSaplingOutput::recipient_pk_d() const noexcept {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  wallet$cxxbridge1$DecryptedSaplingOutput$recipient_pk_d(*this, &return$.value);
  return ::std::move(return$.value);
}

::std::array<::std::uint8_t, 512> DecryptedSaplingOutput::memo() const noexcept {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 512>> return$;
  wallet$cxxbridge1$DecryptedSaplingOutput$memo(*this, &return$.value);
  return ::std::move(return$.value);
}
} // namespace wallet

namespace sapling {
namespace tree {
::std::size_t SaplingFrontier::layout::size() noexcept {
  return sapling$tree$cxxbridge1$SaplingFrontier$operator$sizeof();
}

::std::size_t SaplingFrontier::layout::align() noexcept {
  return sapling$tree$cxxbridge1$SaplingFrontier$operator$alignof();
}

// Create a new empty commitment tree frontier.
::rust::Box<::sapling::tree::SaplingFrontier> new_sapling_frontier() noexcept {
  return ::rust::Box<::sapling::tree::SaplingFrontier>::from_raw(sapling$tree$cxxbridge1$new_sapling_frontier());
}

// Append a note commitment to the frontier.
void frontier_append(::sapling::tree::SaplingFrontier &tree, ::std::array<::std::uint8_t, 32> const &cmu) {
  ::rust::repr::PtrLen error$ = sapling$tree$cxxbridge1$frontier_append(tree, cmu);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
}

// Get the Merkle root hash of the frontier.
::std::array<::std::uint8_t, 32> frontier_root(::sapling::tree::SaplingFrontier const &tree) noexcept {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  sapling$tree$cxxbridge1$frontier_root(tree, &return$.value);
  return ::std::move(return$.value);
}

// Number of leaves in the tree.
::std::uint64_t frontier_size(::sapling::tree::SaplingFrontier const &tree) noexcept {
  return sapling$tree$cxxbridge1$frontier_size(tree);
}

// Serialize the frontier for LevelDB storage.
::rust::Vec<::std::uint8_t> frontier_serialize(::sapling::tree::SaplingFrontier const &tree) noexcept {
  ::rust::MaybeUninit<::rust::Vec<::std::uint8_t>> return$;
  sapling$tree$cxxbridge1$frontier_serialize(tree, &return$.value);
  return ::std::move(return$.value);
}

// Deserialize a frontier from bytes.
::rust::Box<::sapling::tree::SaplingFrontier> frontier_deserialize(::rust::Slice<::std::uint8_t const> data) {
  ::rust::MaybeUninit<::rust::Box<::sapling::tree::SaplingFrontier>> return$;
  ::rust::repr::PtrLen error$ = sapling$tree$cxxbridge1$frontier_deserialize(data, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

::std::size_t SaplingWitness::layout::size() noexcept {
  return sapling$tree$cxxbridge1$SaplingWitness$operator$sizeof();
}

::std::size_t SaplingWitness::layout::align() noexcept {
  return sapling$tree$cxxbridge1$SaplingWitness$operator$alignof();
}

// Create a witness for the most recently appended leaf.
::rust::Box<::sapling::tree::SaplingWitness> witness_from_frontier(::sapling::tree::SaplingFrontier const &tree) {
  ::rust::MaybeUninit<::rust::Box<::sapling::tree::SaplingWitness>> return$;
  ::rust::repr::PtrLen error$ = sapling$tree$cxxbridge1$witness_from_frontier(tree, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

// Update the witness with a new commitment.
void witness_append(::sapling::tree::SaplingWitness &wit, ::std::array<::std::uint8_t, 32> const &cmu) {
  ::rust::repr::PtrLen error$ = sapling$tree$cxxbridge1$witness_append(wit, cmu);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
}

// Get the Merkle root from the witness.
::std::array<::std::uint8_t, 32> witness_root(::sapling::tree::SaplingWitness const &wit) noexcept {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  sapling$tree$cxxbridge1$witness_root(wit, &return$.value);
  return ::std::move(return$.value);
}

// Get the position of the witnessed leaf.
::std::uint64_t witness_position(::sapling::tree::SaplingWitness const &wit) noexcept {
  return sapling$tree$cxxbridge1$witness_position(wit);
}

// Get the 1065-byte Merkle path for the Sapling prover.
::std::array<::std::uint8_t, 1065> witness_path(::sapling::tree::SaplingWitness const &wit) {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 1065>> return$;
  ::rust::repr::PtrLen error$ = sapling$tree$cxxbridge1$witness_path(wit, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

// Serialize the witness for wallet storage.
::rust::Vec<::std::uint8_t> witness_serialize(::sapling::tree::SaplingWitness const &wit) noexcept {
  ::rust::MaybeUninit<::rust::Vec<::std::uint8_t>> return$;
  sapling$tree$cxxbridge1$witness_serialize(wit, &return$.value);
  return ::std::move(return$.value);
}

// Deserialize a witness from bytes.
::rust::Box<::sapling::tree::SaplingWitness> witness_deserialize(::rust::Slice<::std::uint8_t const> data) {
  ::rust::MaybeUninit<::rust::Box<::sapling::tree::SaplingWitness>> return$;
  ::rust::repr::PtrLen error$ = sapling$tree$cxxbridge1$witness_deserialize(data, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}
} // namespace tree

// Load Sapling zk-SNARK parameters from disk.
// Verifies file integrity (size + BLAKE2b hash) before use.
void init_sapling_params(::rust::Str spend_path, ::rust::Str output_path) {
  ::rust::repr::PtrLen error$ = sapling$cxxbridge1$init_sapling_params(spend_path, output_path);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
}

// Returns true if Sapling parameters have been loaded.
bool is_sapling_initialized() noexcept {
  return sapling$cxxbridge1$is_sapling_initialized();
}
} // namespace sapling

namespace hmp {
// Initialize HMP Groth16 parameters (trusted setup).
// Generates parameters for the MiMC commitment circuit.
void init_hmp_params() {
  ::rust::repr::PtrLen error$ = hmp$cxxbridge1$init_hmp_params();
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
}

// Returns true if HMP parameters have been initialized.
bool is_hmp_initialized() noexcept {
  return hmp$cxxbridge1$is_hmp_initialized();
}

// Create a Groth16 participation proof (192 bytes).
::rust::Vec<::std::uint8_t> hmp_create_proof(::std::array<::std::uint8_t, 32> const &sk_bytes, ::std::array<::std::uint8_t, 32> const &block_hash, ::std::array<::std::uint8_t, 32> const &chain_state_hash) {
  ::rust::MaybeUninit<::rust::Vec<::std::uint8_t>> return$;
  ::rust::repr::PtrLen error$ = hmp$cxxbridge1$hmp_create_proof(sk_bytes, block_hash, chain_state_hash, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

// Verify a Groth16 participation proof.
bool hmp_verify_proof(::rust::Slice<::std::uint8_t const> proof_bytes, ::std::array<::std::uint8_t, 32> const &block_hash, ::std::array<::std::uint8_t, 32> const &commitment) {
  ::rust::MaybeUninit<bool> return$;
  ::rust::repr::PtrLen error$ = hmp$cxxbridge1$hmp_verify_proof(proof_bytes, block_hash, commitment, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}

// Compute commitment for given inputs (used by prover and verifier).
::std::array<::std::uint8_t, 32> hmp_compute_commitment(::std::array<::std::uint8_t, 32> const &sk_bytes, ::std::array<::std::uint8_t, 32> const &block_hash, ::std::array<::std::uint8_t, 32> const &chain_state_hash) {
  ::rust::MaybeUninit<::std::array<::std::uint8_t, 32>> return$;
  ::rust::repr::PtrLen error$ = hmp$cxxbridge1$hmp_compute_commitment(sk_bytes, block_hash, chain_state_hash, &return$.value);
  if (error$.ptr) {
    throw ::rust::impl<::rust::Error>::error(error$);
  }
  return ::std::move(return$.value);
}
} // namespace hmp

extern "C" {
::stream::CppStream *cxxbridge1$box$stream$CppStream$alloc() noexcept;
void cxxbridge1$box$stream$CppStream$dealloc(::stream::CppStream *) noexcept;
void cxxbridge1$box$stream$CppStream$drop(::rust::Box<::stream::CppStream> *ptr) noexcept;

::consensus::Network *cxxbridge1$box$consensus$Network$alloc() noexcept;
void cxxbridge1$box$consensus$Network$dealloc(::consensus::Network *) noexcept;
void cxxbridge1$box$consensus$Network$drop(::rust::Box<::consensus::Network> *ptr) noexcept;

static_assert(::rust::detail::is_complete<::std::remove_extent<::libkerrigan::BundleValidityCache>::type>::value, "definition of `::libkerrigan::BundleValidityCache` is required");
static_assert(sizeof(::std::unique_ptr<::libkerrigan::BundleValidityCache>) == sizeof(void *), "");
static_assert(alignof(::std::unique_ptr<::libkerrigan::BundleValidityCache>) == alignof(void *), "");
void cxxbridge1$unique_ptr$libkerrigan$BundleValidityCache$null(::std::unique_ptr<::libkerrigan::BundleValidityCache> *ptr) noexcept {
  ::new (ptr) ::std::unique_ptr<::libkerrigan::BundleValidityCache>();
}
void cxxbridge1$unique_ptr$libkerrigan$BundleValidityCache$raw(::std::unique_ptr<::libkerrigan::BundleValidityCache> *ptr, ::std::unique_ptr<::libkerrigan::BundleValidityCache>::pointer raw) noexcept {
  ::new (ptr) ::std::unique_ptr<::libkerrigan::BundleValidityCache>(raw);
}
::std::unique_ptr<::libkerrigan::BundleValidityCache>::element_type const *cxxbridge1$unique_ptr$libkerrigan$BundleValidityCache$get(::std::unique_ptr<::libkerrigan::BundleValidityCache> const &ptr) noexcept {
  return ptr.get();
}
::std::unique_ptr<::libkerrigan::BundleValidityCache>::pointer cxxbridge1$unique_ptr$libkerrigan$BundleValidityCache$release(::std::unique_ptr<::libkerrigan::BundleValidityCache> &ptr) noexcept {
  return ptr.release();
}
void cxxbridge1$unique_ptr$libkerrigan$BundleValidityCache$drop(::std::unique_ptr<::libkerrigan::BundleValidityCache> *ptr) noexcept {
  ::rust::deleter_if<::rust::detail::is_complete<::libkerrigan::BundleValidityCache>::value>{}(ptr);
}

::sapling::Spend *cxxbridge1$box$sapling$Spend$alloc() noexcept;
void cxxbridge1$box$sapling$Spend$dealloc(::sapling::Spend *) noexcept;
void cxxbridge1$box$sapling$Spend$drop(::rust::Box<::sapling::Spend> *ptr) noexcept;

::sapling::Output *cxxbridge1$box$sapling$Output$alloc() noexcept;
void cxxbridge1$box$sapling$Output$dealloc(::sapling::Output *) noexcept;
void cxxbridge1$box$sapling$Output$drop(::rust::Box<::sapling::Output> *ptr) noexcept;

::sapling::Bundle *cxxbridge1$box$sapling$Bundle$alloc() noexcept;
void cxxbridge1$box$sapling$Bundle$dealloc(::sapling::Bundle *) noexcept;
void cxxbridge1$box$sapling$Bundle$drop(::rust::Box<::sapling::Bundle> *ptr) noexcept;

void cxxbridge1$rust_vec$sapling$Spend$new(::rust::Vec<::sapling::Spend> const *ptr) noexcept;
void cxxbridge1$rust_vec$sapling$Spend$drop(::rust::Vec<::sapling::Spend> *ptr) noexcept;
::std::size_t cxxbridge1$rust_vec$sapling$Spend$len(::rust::Vec<::sapling::Spend> const *ptr) noexcept;
::std::size_t cxxbridge1$rust_vec$sapling$Spend$capacity(::rust::Vec<::sapling::Spend> const *ptr) noexcept;
::sapling::Spend const *cxxbridge1$rust_vec$sapling$Spend$data(::rust::Vec<::sapling::Spend> const *ptr) noexcept;
void cxxbridge1$rust_vec$sapling$Spend$reserve_total(::rust::Vec<::sapling::Spend> *ptr, ::std::size_t new_cap) noexcept;
void cxxbridge1$rust_vec$sapling$Spend$set_len(::rust::Vec<::sapling::Spend> *ptr, ::std::size_t len) noexcept;
void cxxbridge1$rust_vec$sapling$Spend$truncate(::rust::Vec<::sapling::Spend> *ptr, ::std::size_t len) noexcept;

void cxxbridge1$rust_vec$sapling$Output$new(::rust::Vec<::sapling::Output> const *ptr) noexcept;
void cxxbridge1$rust_vec$sapling$Output$drop(::rust::Vec<::sapling::Output> *ptr) noexcept;
::std::size_t cxxbridge1$rust_vec$sapling$Output$len(::rust::Vec<::sapling::Output> const *ptr) noexcept;
::std::size_t cxxbridge1$rust_vec$sapling$Output$capacity(::rust::Vec<::sapling::Output> const *ptr) noexcept;
::sapling::Output const *cxxbridge1$rust_vec$sapling$Output$data(::rust::Vec<::sapling::Output> const *ptr) noexcept;
void cxxbridge1$rust_vec$sapling$Output$reserve_total(::rust::Vec<::sapling::Output> *ptr, ::std::size_t new_cap) noexcept;
void cxxbridge1$rust_vec$sapling$Output$set_len(::rust::Vec<::sapling::Output> *ptr, ::std::size_t len) noexcept;
void cxxbridge1$rust_vec$sapling$Output$truncate(::rust::Vec<::sapling::Output> *ptr, ::std::size_t len) noexcept;

::sapling::BundleAssembler *cxxbridge1$box$sapling$BundleAssembler$alloc() noexcept;
void cxxbridge1$box$sapling$BundleAssembler$dealloc(::sapling::BundleAssembler *) noexcept;
void cxxbridge1$box$sapling$BundleAssembler$drop(::rust::Box<::sapling::BundleAssembler> *ptr) noexcept;

::sapling::Builder *cxxbridge1$box$sapling$Builder$alloc() noexcept;
void cxxbridge1$box$sapling$Builder$dealloc(::sapling::Builder *) noexcept;
void cxxbridge1$box$sapling$Builder$drop(::rust::Box<::sapling::Builder> *ptr) noexcept;

::sapling::UnauthorizedBundle *cxxbridge1$box$sapling$UnauthorizedBundle$alloc() noexcept;
void cxxbridge1$box$sapling$UnauthorizedBundle$dealloc(::sapling::UnauthorizedBundle *) noexcept;
void cxxbridge1$box$sapling$UnauthorizedBundle$drop(::rust::Box<::sapling::UnauthorizedBundle> *ptr) noexcept;

::sapling::Verifier *cxxbridge1$box$sapling$Verifier$alloc() noexcept;
void cxxbridge1$box$sapling$Verifier$dealloc(::sapling::Verifier *) noexcept;
void cxxbridge1$box$sapling$Verifier$drop(::rust::Box<::sapling::Verifier> *ptr) noexcept;

::sapling::BatchValidator *cxxbridge1$box$sapling$BatchValidator$alloc() noexcept;
void cxxbridge1$box$sapling$BatchValidator$dealloc(::sapling::BatchValidator *) noexcept;
void cxxbridge1$box$sapling$BatchValidator$drop(::rust::Box<::sapling::BatchValidator> *ptr) noexcept;

::wallet::DecryptedSaplingOutput *cxxbridge1$box$wallet$DecryptedSaplingOutput$alloc() noexcept;
void cxxbridge1$box$wallet$DecryptedSaplingOutput$dealloc(::wallet::DecryptedSaplingOutput *) noexcept;
void cxxbridge1$box$wallet$DecryptedSaplingOutput$drop(::rust::Box<::wallet::DecryptedSaplingOutput> *ptr) noexcept;

::sapling::tree::SaplingFrontier *cxxbridge1$box$sapling$tree$SaplingFrontier$alloc() noexcept;
void cxxbridge1$box$sapling$tree$SaplingFrontier$dealloc(::sapling::tree::SaplingFrontier *) noexcept;
void cxxbridge1$box$sapling$tree$SaplingFrontier$drop(::rust::Box<::sapling::tree::SaplingFrontier> *ptr) noexcept;

::sapling::tree::SaplingWitness *cxxbridge1$box$sapling$tree$SaplingWitness$alloc() noexcept;
void cxxbridge1$box$sapling$tree$SaplingWitness$dealloc(::sapling::tree::SaplingWitness *) noexcept;
void cxxbridge1$box$sapling$tree$SaplingWitness$drop(::rust::Box<::sapling::tree::SaplingWitness> *ptr) noexcept;
} // extern "C"

namespace rust {
inline namespace cxxbridge1 {
template <>
::stream::CppStream *Box<::stream::CppStream>::allocation::alloc() noexcept {
  return cxxbridge1$box$stream$CppStream$alloc();
}
template <>
void Box<::stream::CppStream>::allocation::dealloc(::stream::CppStream *ptr) noexcept {
  cxxbridge1$box$stream$CppStream$dealloc(ptr);
}
template <>
void Box<::stream::CppStream>::drop() noexcept {
  cxxbridge1$box$stream$CppStream$drop(this);
}
template <>
::consensus::Network *Box<::consensus::Network>::allocation::alloc() noexcept {
  return cxxbridge1$box$consensus$Network$alloc();
}
template <>
void Box<::consensus::Network>::allocation::dealloc(::consensus::Network *ptr) noexcept {
  cxxbridge1$box$consensus$Network$dealloc(ptr);
}
template <>
void Box<::consensus::Network>::drop() noexcept {
  cxxbridge1$box$consensus$Network$drop(this);
}
template <>
::sapling::Spend *Box<::sapling::Spend>::allocation::alloc() noexcept {
  return cxxbridge1$box$sapling$Spend$alloc();
}
template <>
void Box<::sapling::Spend>::allocation::dealloc(::sapling::Spend *ptr) noexcept {
  cxxbridge1$box$sapling$Spend$dealloc(ptr);
}
template <>
void Box<::sapling::Spend>::drop() noexcept {
  cxxbridge1$box$sapling$Spend$drop(this);
}
template <>
::sapling::Output *Box<::sapling::Output>::allocation::alloc() noexcept {
  return cxxbridge1$box$sapling$Output$alloc();
}
template <>
void Box<::sapling::Output>::allocation::dealloc(::sapling::Output *ptr) noexcept {
  cxxbridge1$box$sapling$Output$dealloc(ptr);
}
template <>
void Box<::sapling::Output>::drop() noexcept {
  cxxbridge1$box$sapling$Output$drop(this);
}
template <>
::sapling::Bundle *Box<::sapling::Bundle>::allocation::alloc() noexcept {
  return cxxbridge1$box$sapling$Bundle$alloc();
}
template <>
void Box<::sapling::Bundle>::allocation::dealloc(::sapling::Bundle *ptr) noexcept {
  cxxbridge1$box$sapling$Bundle$dealloc(ptr);
}
template <>
void Box<::sapling::Bundle>::drop() noexcept {
  cxxbridge1$box$sapling$Bundle$drop(this);
}
template <>
Vec<::sapling::Spend>::Vec() noexcept {
  cxxbridge1$rust_vec$sapling$Spend$new(this);
}
template <>
void Vec<::sapling::Spend>::drop() noexcept {
  return cxxbridge1$rust_vec$sapling$Spend$drop(this);
}
template <>
::std::size_t Vec<::sapling::Spend>::size() const noexcept {
  return cxxbridge1$rust_vec$sapling$Spend$len(this);
}
template <>
::std::size_t Vec<::sapling::Spend>::capacity() const noexcept {
  return cxxbridge1$rust_vec$sapling$Spend$capacity(this);
}
template <>
::sapling::Spend const *Vec<::sapling::Spend>::data() const noexcept {
  return cxxbridge1$rust_vec$sapling$Spend$data(this);
}
template <>
void Vec<::sapling::Spend>::reserve_total(::std::size_t new_cap) noexcept {
  return cxxbridge1$rust_vec$sapling$Spend$reserve_total(this, new_cap);
}
template <>
void Vec<::sapling::Spend>::set_len(::std::size_t len) noexcept {
  return cxxbridge1$rust_vec$sapling$Spend$set_len(this, len);
}
template <>
void Vec<::sapling::Spend>::truncate(::std::size_t len) {
  return cxxbridge1$rust_vec$sapling$Spend$truncate(this, len);
}
template <>
Vec<::sapling::Output>::Vec() noexcept {
  cxxbridge1$rust_vec$sapling$Output$new(this);
}
template <>
void Vec<::sapling::Output>::drop() noexcept {
  return cxxbridge1$rust_vec$sapling$Output$drop(this);
}
template <>
::std::size_t Vec<::sapling::Output>::size() const noexcept {
  return cxxbridge1$rust_vec$sapling$Output$len(this);
}
template <>
::std::size_t Vec<::sapling::Output>::capacity() const noexcept {
  return cxxbridge1$rust_vec$sapling$Output$capacity(this);
}
template <>
::sapling::Output const *Vec<::sapling::Output>::data() const noexcept {
  return cxxbridge1$rust_vec$sapling$Output$data(this);
}
template <>
void Vec<::sapling::Output>::reserve_total(::std::size_t new_cap) noexcept {
  return cxxbridge1$rust_vec$sapling$Output$reserve_total(this, new_cap);
}
template <>
void Vec<::sapling::Output>::set_len(::std::size_t len) noexcept {
  return cxxbridge1$rust_vec$sapling$Output$set_len(this, len);
}
template <>
void Vec<::sapling::Output>::truncate(::std::size_t len) {
  return cxxbridge1$rust_vec$sapling$Output$truncate(this, len);
}
template <>
::sapling::BundleAssembler *Box<::sapling::BundleAssembler>::allocation::alloc() noexcept {
  return cxxbridge1$box$sapling$BundleAssembler$alloc();
}
template <>
void Box<::sapling::BundleAssembler>::allocation::dealloc(::sapling::BundleAssembler *ptr) noexcept {
  cxxbridge1$box$sapling$BundleAssembler$dealloc(ptr);
}
template <>
void Box<::sapling::BundleAssembler>::drop() noexcept {
  cxxbridge1$box$sapling$BundleAssembler$drop(this);
}
template <>
::sapling::Builder *Box<::sapling::Builder>::allocation::alloc() noexcept {
  return cxxbridge1$box$sapling$Builder$alloc();
}
template <>
void Box<::sapling::Builder>::allocation::dealloc(::sapling::Builder *ptr) noexcept {
  cxxbridge1$box$sapling$Builder$dealloc(ptr);
}
template <>
void Box<::sapling::Builder>::drop() noexcept {
  cxxbridge1$box$sapling$Builder$drop(this);
}
template <>
::sapling::UnauthorizedBundle *Box<::sapling::UnauthorizedBundle>::allocation::alloc() noexcept {
  return cxxbridge1$box$sapling$UnauthorizedBundle$alloc();
}
template <>
void Box<::sapling::UnauthorizedBundle>::allocation::dealloc(::sapling::UnauthorizedBundle *ptr) noexcept {
  cxxbridge1$box$sapling$UnauthorizedBundle$dealloc(ptr);
}
template <>
void Box<::sapling::UnauthorizedBundle>::drop() noexcept {
  cxxbridge1$box$sapling$UnauthorizedBundle$drop(this);
}
template <>
::sapling::Verifier *Box<::sapling::Verifier>::allocation::alloc() noexcept {
  return cxxbridge1$box$sapling$Verifier$alloc();
}
template <>
void Box<::sapling::Verifier>::allocation::dealloc(::sapling::Verifier *ptr) noexcept {
  cxxbridge1$box$sapling$Verifier$dealloc(ptr);
}
template <>
void Box<::sapling::Verifier>::drop() noexcept {
  cxxbridge1$box$sapling$Verifier$drop(this);
}
template <>
::sapling::BatchValidator *Box<::sapling::BatchValidator>::allocation::alloc() noexcept {
  return cxxbridge1$box$sapling$BatchValidator$alloc();
}
template <>
void Box<::sapling::BatchValidator>::allocation::dealloc(::sapling::BatchValidator *ptr) noexcept {
  cxxbridge1$box$sapling$BatchValidator$dealloc(ptr);
}
template <>
void Box<::sapling::BatchValidator>::drop() noexcept {
  cxxbridge1$box$sapling$BatchValidator$drop(this);
}
template <>
::wallet::DecryptedSaplingOutput *Box<::wallet::DecryptedSaplingOutput>::allocation::alloc() noexcept {
  return cxxbridge1$box$wallet$DecryptedSaplingOutput$alloc();
}
template <>
void Box<::wallet::DecryptedSaplingOutput>::allocation::dealloc(::wallet::DecryptedSaplingOutput *ptr) noexcept {
  cxxbridge1$box$wallet$DecryptedSaplingOutput$dealloc(ptr);
}
template <>
void Box<::wallet::DecryptedSaplingOutput>::drop() noexcept {
  cxxbridge1$box$wallet$DecryptedSaplingOutput$drop(this);
}
template <>
::sapling::tree::SaplingFrontier *Box<::sapling::tree::SaplingFrontier>::allocation::alloc() noexcept {
  return cxxbridge1$box$sapling$tree$SaplingFrontier$alloc();
}
template <>
void Box<::sapling::tree::SaplingFrontier>::allocation::dealloc(::sapling::tree::SaplingFrontier *ptr) noexcept {
  cxxbridge1$box$sapling$tree$SaplingFrontier$dealloc(ptr);
}
template <>
void Box<::sapling::tree::SaplingFrontier>::drop() noexcept {
  cxxbridge1$box$sapling$tree$SaplingFrontier$drop(this);
}
template <>
::sapling::tree::SaplingWitness *Box<::sapling::tree::SaplingWitness>::allocation::alloc() noexcept {
  return cxxbridge1$box$sapling$tree$SaplingWitness$alloc();
}
template <>
void Box<::sapling::tree::SaplingWitness>::allocation::dealloc(::sapling::tree::SaplingWitness *ptr) noexcept {
  cxxbridge1$box$sapling$tree$SaplingWitness$dealloc(ptr);
}
template <>
void Box<::sapling::tree::SaplingWitness>::drop() noexcept {
  cxxbridge1$box$sapling$tree$SaplingWitness$drop(this);
}
} // namespace cxxbridge1
} // namespace rust
