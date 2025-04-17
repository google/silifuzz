// Copyright 2022 The SiliFuzz Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_ITOA_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_ITOA_H_

// This library defines simple int->string converters that work without
// bringing in libc dependencies and heap allocation.
// All the memory needed is within the temporary itoa_internal::IntStr or
// itoa_internal::HexStr object.

#include <cstdint>
#include <type_traits>  // for std::enable_if_t, std::is_enum

namespace silifuzz {

namespace itoa_internal {
// Impl for IntStr() below.
// This class is a thread-compatible value type.
class IntStr {
 public:
  IntStr(int64_t num);

  IntStr(const IntStr&) = delete;
  IntStr(IntStr&&) = delete;
  IntStr operator=(const IntStr&) = delete;
  IntStr operator=(IntStr&&) = delete;

  const char* c_str() const { return ptr_; }

 protected:  // for ErrnoStr below
  char* ptr_;
  char rep_[22];
};

}  // namespace itoa_internal

// Converts an integer to string representation.
//
// Usage example:
//   int64_t my_int = ...;
//   LOG_ERROR("My int: ", IntStr(my_int));
inline const char* IntStr(const itoa_internal::IntStr& x) { return x.c_str(); }

// ========================================================================= //

namespace itoa_internal {
// Impl for ErrnoStr() below.
class ErrnoStr final : public IntStr {
 public:
  ErrnoStr(int num);
};
}  // namespace itoa_internal

// Use this instead of IntStr() for errno values.
// Use the `errno` command line utility to look up the name and description of a
// specific errno number. (See `man errno.1`)
//
// Usage example:
//   int my_errno = ...;
//   LOG_ERROR("My errno: ", ErrnoStr(my_errno));
inline const char* ErrnoStr(const itoa_internal::ErrnoStr& x) {
  return x.c_str();
}

// ========================================================================= //

namespace itoa_internal {
// Impl for HexStr() below.
// This class is a thread-compatible value type.
class HexStr final {
 public:
  HexStr(__uint128_t num);
  template <typename T>
  HexStr(const T* ptr) : HexStr(reinterpret_cast<uint64_t>(ptr)) {}

  HexStr(const HexStr&) = delete;
  HexStr(HexStr&&) = delete;
  HexStr operator=(const HexStr&) = delete;
  HexStr operator=(HexStr&&) = delete;

  const char* c_str() const { return ptr_; }

 private:
  char* ptr_;
  char rep_[35];
};
}  // namespace itoa_internal

// Converts an integer or a pointer to hex string representation
// including the "0x" prefix.
//
// Usage example:
//   int64_t my_int = ...;
//   LOG_ERROR("My int: ", HexStr(my_int));
inline const char* HexStr(const itoa_internal::HexStr& x) { return x.c_str(); }

// Same as HexStr(), but without the "0x" prefix.
inline const char* HexStrDigits(const itoa_internal::HexStr& x) {
  return x.c_str() + 2;
}

// ========================================================================= //

// Converts a bool to string representation.
//
// Usage example:
//   bool my_bool = ...;
//   LOG_ERROR("My bool: ", BoolStr(my_bool));
const char* BoolStr(bool b);

// ========================================================================= //

// Specialize this to define EnumStr() helper below.
// Usage example:
//
//   enum MyEnum { kA = 0, kB};
//
//   // In the same .h as MyEnum (has to be in silifuzz namespace same as
//   // original EnumNameMap template):
//   template<>
//   inline constexpr const char* EnumNameMap<MyEnum>[2];
//
//   // In another .h or .cc:
//   ... EnumStr(my_enum) ...
//
// Enum values need to be reasonably gap-free and non-negative for EnumNameMap
// to provide names for them: the first array element is for enum value 0,
// the next is for enum value 1, and so forth; use nullptr for gaps
// (if there's no enum constant with a given value).
// We do not use real map<> here so that this library works in the nolibc
// no-allocations case.
template <typename EnumT, std::enable_if_t<std::is_enum<EnumT>::value, int> = 0>
const char* EnumNameMap[] = {};

// Converts an enum to string representation based on the names given
// via the EnumNameMap<MyEnum> specialization.
//
// Usage example:
//   MyEnum my_enum = ...;
//   LOG_ERROR("My enum: ", EnumStr(my_enum));
template <typename EnumT, std::enable_if_t<std::is_enum<EnumT>::value, int> = 0>
const char* EnumStr(EnumT e) {
  int i = static_cast<int>(e);
  // Not using std::size() here as we want to support 0-sized arrays too.
  if (i < 0 || i >= sizeof(EnumNameMap<EnumT>) / sizeof(const char*) ||
      EnumNameMap<EnumT>[i] == nullptr)
    return "NO-ENUM-NAME-DEFINED";
  return EnumNameMap<EnumT>[i];
}

// ========================================================================= //

// Returns signal names exactly as `kill -l` prints them.
// This routine is (and must remain) async-signal-safe.
// NOTE: strsignal.3 returns signal descriptions, such as "Segmentation fault",
// rather than the technical names, and is thread- and async-signal-unsafe.
// sigdabbrev_np.3 would do, but is unavailable in GRTE's glibc.
const char* SignalNameStr(int signal);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_ITOA_H_
