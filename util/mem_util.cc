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

#include "./util/mem_util.h"

#include <strings.h>

#include <cstdint>
#include <cstring>

namespace silifuzz {

// The no_builtin attribute tells a compiler not replace any part of this
// function with a call to memcpy(). An optimizing compiler can recognize
// the uint64_t copying loop below and replace that with a call to memcpy(),
// depending on optimization setting.
void MemCopy(void* dest, const void* src, size_t n)
    __attribute__((no_builtin("memcpy"))) {
  // Optimize only if dest, src and n are all 8-byte aligned.
  if (reinterpret_cast<uintptr_t>(dest) % sizeof(uint64_t) != 0 ||
      reinterpret_cast<uintptr_t>(src) % sizeof(uint64_t) != 0 ||
      n % sizeof(uint64_t) != 0) {
    uint8_t* dest_u8 = reinterpret_cast<uint8_t*>(dest);
    const uint8_t* src_u8 = reinterpret_cast<const uint8_t*>(src);
    for (size_t i = 0; i < n; ++i) {
      dest_u8[i] = src_u8[i];
    }
    return;
  }

  const size_t num_u64s = n / sizeof(uint64_t);
  uint64_t* dest_u64 = reinterpret_cast<uint64_t*>(dest);
  const uint64_t* src_u64 = reinterpret_cast<const uint64_t*>(src);
  for (size_t i = 0; i < num_u64s; ++i) {
    dest_u64[i] = src_u64[i];
  }
}

void MemSet(void* dest, uint8_t c, size_t n)
    __attribute__((no_builtin("memset"))) /* see MemCopy() above */ {
  // Optimize only if dest and n are both 8-byte aligned.
  if (reinterpret_cast<uintptr_t>(dest) % sizeof(uint64_t) != 0 ||
      n % sizeof(uint64_t) != 0) {
    uint8_t* dest_u8 = reinterpret_cast<uint8_t*>(dest);
    for (size_t i = 0; i < n; ++i) {
      dest_u8[i] = c;
    }
    return;
  }

  const size_t num_u64s = n / sizeof(uint64_t);
  uint64_t* dest_u64 = reinterpret_cast<uint64_t*>(dest);
  const uint64_t c_u64 = c * 0x0101010101010101ULL;  // replicate 8 times.
  for (size_t i = 0; i < num_u64s; ++i) {
    dest_u64[i] = c_u64;
  }
}

bool MemEq(const void* s1, const void* s2, size_t n)
    __attribute__((no_builtin("memcmp"))) /* See MemCopy() above */ {
  // Optimize only if s1, s2 and n are all 8-byte aligned.
  if (reinterpret_cast<uintptr_t>(s1) % sizeof(uint64_t) != 0 ||
      reinterpret_cast<uintptr_t>(s2) % sizeof(uint64_t) != 0 ||
      n % sizeof(uint64_t) != 0) {
    return bcmp(s1, s2, n) == 0;
  }

  // This is used in the runner to check that memory contents are
  // equal. It is optimized for the positive case. We accumulate pair-wise
  // XOR results and OR them together to check at the end.  This reduces
  // the number of branch instructions executed by the CPU.
  const size_t num_u64s = n / sizeof(uint64_t);
  const uint64_t* u1 = reinterpret_cast<const uint64_t*>(s1);
  const uint64_t* u2 = reinterpret_cast<const uint64_t*>(s2);
  uint64_t diff = 0;
  for (size_t i = 0; i < num_u64s; ++i) {
    diff |= u1[i] ^ u2[i];
  }
  return diff == 0;
}

// This is used in the runner to check that memory contents are
// equal. It is optimized for the positive case.
bool MemAllEqualTo(const void* src, uint8_t c, size_t n) {
  // Optimize only if src and n are both 8-byte aligned.
  if (reinterpret_cast<uintptr_t>(src) % sizeof(uint64_t) == 0 &&
      n % sizeof(uint64_t) == 0) {
    const size_t num_u64s = n / sizeof(uint64_t);
    const uint64_t* src_u64 = reinterpret_cast<const uint64_t*>(src);
    const uint64_t c_u64 = c * 0x0101010101010101ULL;  // replicate 8 times.
    uint64_t diff = 0;
    for (size_t i = 0; i < num_u64s; ++i) {
      diff |= src_u64[i] ^ c_u64;
    }
    return diff == 0;
  } else {
    // Simple byte loop for the non-optimized case.
    const uint8_t* src_u8 = reinterpret_cast<const uint8_t*>(src);
    for (size_t i = 0; i < n; ++i) {
      if (src_u8[i] != c) {
        return false;
      }
    }
    return true;
  }
}

}  // namespace silifuzz
