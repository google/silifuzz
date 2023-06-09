// Copyright 2023 The SiliFuzz Authors.
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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_REG_GROUP_SET_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_REG_GROUP_SET_H_

#include <cstddef>

#include "./util/arch.h"
#include "./util/reg_group_bits.h"
namespace silifuzz {

// A RegisterGroupSet object represents a collection of register groups
// of the architecture specified by its template argument. Unlike most
// other set implementation, for each element that RegisterGroupSet can hold, a
// pair of dedicated accessors are defined. A getter GET<element_name>()
// returns whether the said element is present or not and A setter
// SET<element_name>() sets a value indicating whether the element is
// present. In addition to these accessors, RegisterGroupSet provides
// methods for a few other operation like checks for emptiness and
// set equality.
// Finally, RegisterGroupSet can be converted to and from the uint64_t
// for serialization. The conversion is based on architecture-specific
// bit values defined reg_groups_bits.h. The conversion is stable.
template <typename Arch>
class RegisterGroupSet;

// ------------------------ x86-64 register group set -------------------------

template <>
class RegisterGroupSet<X86_64> {
 public:
  constexpr RegisterGroupSet() : RegisterGroupSet(0) {}
  ~RegisterGroupSet() = default;

  // Copyable and movable.
  constexpr RegisterGroupSet(const RegisterGroupSet&) = default;
  constexpr RegisterGroupSet& operator=(const RegisterGroupSet&) = default;
  RegisterGroupSet(RegisterGroupSet&&) = default;
  RegisterGroupSet& operator=(RegisterGroupSet&&) = default;

  // Equality operators.
  constexpr bool operator==(const RegisterGroupSet<X86_64>& other) const {
    return bits_ == other.bits_;
  }
  constexpr bool operator!=(const RegisterGroupSet<X86_64>& other) const {
    return !(*this == other);
  }

  constexpr bool Empty() const { return bits_ == 0; }

  // Accessors for groups within this set.
  constexpr bool GetGPR() const { return GetBit(X86_REG_GROUP_GPR); }

  RegisterGroupSet<X86_64>& SetGPR(bool v) {
    return SetBit(X86_REG_GROUP_GPR, v);
  }

  constexpr bool GetFPRAndSSE() const {
    return GetBit(X86_REG_GROUP_FPR_AND_SSE);
  }

  RegisterGroupSet<X86_64>& SetFPRAndSSE(bool v) {
    return SetBit(X86_REG_GROUP_FPR_AND_SSE, v);
  }

  constexpr bool GetAVX() const { return GetBit(X86_REG_GROUP_AVX); }

  RegisterGroupSet<X86_64>& SetAVX(bool v) {
    return SetBit(X86_REG_GROUP_AVX, v);
  }

  constexpr bool GetAVX512() const { return GetBit(X86_REG_GROUP_AVX512); }

  RegisterGroupSet<X86_64>& SetAVX512(bool v) {
    return SetBit(X86_REG_GROUP_AVX512, v);
  }

  constexpr bool GetAMX() const { return GetBit(X86_REG_GROUP_AMX); }

  RegisterGroupSet<X86_64>& SetAMX(bool v) {
    return SetBit(X86_REG_GROUP_AMX, v);
  }

  // Returns a bit mask representing this using x86 register group bits
  // defined in reg_group.bits.h
  constexpr uint64_t Serialize() const { return bits_; }

  // Returns a new RegisterGroupSet object containing x86-64 register
  // groups described by 'bits'.
  static constexpr RegisterGroupSet<X86_64> Deserialize(uint64_t bits) {
    return RegisterGroupSet(bits);
  }

 private:
  // This version of constructor is not part of the public interface.
  explicit constexpr RegisterGroupSet(uint64_t bits) : bits_(bits) {}

  constexpr bool GetBit(uint64_t bit) const { return (bit & bits_) != 0; }

  RegisterGroupSet<X86_64>& SetBit(uint64_t bit, bool value) {
    if (value) {
      bits_ |= bit;
    } else {
      bits_ &= ~bit;
    }
    return *this;
  }

  // RegisterGroupSet is used by some assembly code that needs to know the
  // layout of the class. The static_assert is put inside a dummy method
  // so that it can access a private data member. We need to wrap the
  // static_assert with a method as it the class is still being defined and
  // incomplete.
  static void static_checker() {
    static_assert(offsetof(RegisterGroupSet<X86_64>, bits_) == 0);
  }

  // Underlying bit mask.
  uint64_t bits_;
};

// ------------------------ AArch64 register group set ------------------------

template <>
class RegisterGroupSet<AArch64> {
 public:
  constexpr RegisterGroupSet() : RegisterGroupSet(0) {}
  ~RegisterGroupSet() = default;

  // Copyable and movable.
  constexpr RegisterGroupSet(const RegisterGroupSet&) = default;
  constexpr RegisterGroupSet& operator=(const RegisterGroupSet&) = default;
  RegisterGroupSet(RegisterGroupSet&&) = default;
  RegisterGroupSet& operator=(RegisterGroupSet&&) = default;

  // Equality operators.
  constexpr bool operator==(const RegisterGroupSet<AArch64>& other) const {
    return bits_ == other.bits_;
  }
  constexpr bool operator!=(const RegisterGroupSet<AArch64>& other) const {
    return !(*this == other);
  }

  constexpr bool Empty() const { return bits_ == 0; }

  // Accessors for groups within this set.
  constexpr bool GetGPR() const { return GetBit(AARCH64_REG_GROUP_GPR); }

  RegisterGroupSet<AArch64>& SetGPR(bool v) {
    return SetBit(AARCH64_REG_GROUP_GPR, v);
  }

  constexpr bool GetFPR() const { return GetBit(AARCH64_REG_GROUP_FPR); }

  RegisterGroupSet<AArch64>& SetFPR(bool v) {
    return SetBit(AARCH64_REG_GROUP_FPR, v);
  }

  // Returns a bit mask representing this using AArch64 register group bits
  // defined in reg_group.bits.h
  constexpr uint64_t Serialize() const { return bits_; }

  // Returns a new RegisterGroupSet object containing AArch64 register
  // groups described by 'bits'.
  static constexpr RegisterGroupSet<AArch64> Deserialize(uint64_t bits) {
    return RegisterGroupSet(bits);
  }

 private:
  // This version of constructor is not part of the public interface.
  explicit constexpr RegisterGroupSet(uint64_t bits) : bits_(bits) {}

  constexpr bool GetBit(uint64_t bit) const { return (bit & bits_) != 0; }

  RegisterGroupSet<AArch64>& SetBit(uint64_t bit, bool value) {
    if (value) {
      bits_ |= bit;
    } else {
      bits_ &= ~bit;
    }
    return *this;
  }

  // See notes in RegisterGroupSet<X86_64> for details.
  static void static_checker() {
    static_assert(offsetof(RegisterGroupSet<AArch64>, bits_) == 0);
  }

  // Underlying bit mask.
  uint64_t bits_;
};

}  // namespace silifuzz
#endif  // THIRD_PARTY_SILIFUZZ_UTIL_REG_GROUP_SET_H_
