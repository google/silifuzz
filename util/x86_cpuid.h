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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_X86_CPUID_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_X86_CPUID_H_
#if defined(__x86_64__)
#include <cstdint>
#include <cstring>  // memcpy()

namespace silifuzz {

// Result of executing a CPUID intruction on an x86 CPU.
struct X86CPUIDResult {
  uint32_t eax;
  uint32_t ebx;
  uint32_t ecx;
  uint32_t edx;
};

// Execute a CPUID instruction with given EAX and ECX values.
inline void X86CPUID(uint32_t eax, uint32_t ecx, X86CPUIDResult* result) {
  uint32_t ebx, edx;
  asm volatile("cpuid" : "+a"(eax), "=b"(ebx), "+c"(ecx), "=d"(edx));
  result->eax = eax;
  result->ebx = ebx;
  result->ecx = ecx;
  result->edx = edx;
}

// Overload for CPUID functions not using ECX.
inline void X86CPUID(uint32_t eax, X86CPUIDResult* result) {
  X86CPUID(eax, 0, result);
}

// Convenience class for getting x86 vendor ID string.
class X86CPUVendorID {
 public:
  // Byte size of a buffer holding a vendor ID string.  3 words plus '\0'.
  static constexpr size_t kVendorIDStringSize = sizeof(uint32_t) * 3 + 1;

  X86CPUVendorID() {
    X86CPUIDResult result;
    X86CPUID(0x0, &result);
    buffer_[0] = result.ebx;
    buffer_[1] = result.edx;
    buffer_[2] = result.ecx;
    buffer_[3] = 0;  // ensure string is terminated.
  }
  ~X86CPUVendorID() = default;

  // By default copyable and moveable.
  X86CPUVendorID(const X86CPUVendorID&) = default;
  X86CPUVendorID(X86CPUVendorID&&) = default;
  X86CPUVendorID& operator=(const X86CPUVendorID&) = default;
  X86CPUVendorID& operator=(X86CPUVendorID&&) = default;

  // Returns a const pointer to the ID string.
  const char* get() const { return reinterpret_cast<const char*>(buffer_); }

  // Convenience functions for checking vendors.
  bool IsAMD() const { return strcmp(get(), "AuthenticAMD") == 0; }

  bool IsIntel() const { return strcmp(get(), "GenuineIntel") == 0; }

 private:
  static constexpr size_t kNumWords = 4;
  static_assert(kNumWords * sizeof(uint32_t) >= kVendorIDStringSize);

  // Stores vendor ID string plus a null character.
  uint32_t buffer_[kNumWords];
};

}  // namespace silifuzz

#endif  // defined(__x86_64__)

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_X86_CPUID_H_
