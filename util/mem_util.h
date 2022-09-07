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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_MEM_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_MEM_UTIL_H_
#include <cstddef>
#include <cstdint>

// Memory utility functions. These are similar to some functions in <cstring>
// but are optimized for uint64_t data. On x86_64, these are compiled into
// integer code only and do not use SSE instructions. This is done to reduce
// perturbation to the floating pointer/vector unit between snapshot executions.

namespace silifuzz {

// Copies n bytes from address src to address dest. This is similar to memcpy()
// but is optimized for the case that dest, src and n are all aligned by 8.
// Performance may degrade significantly for all other cases.
//
// REQUIRES: [dest, dest+n) and [src, src+n) do not overlap.
void MemCopy(void* dest, const void* src, size_t n);

// Sets n bytes at address dest to the same value c. This is similar to memset()
// in lib C but is optimized for the case that dest and n are both aligned by 8.
// Performance may degrade significantly for all other cases.
void MemSet(void* dest, uint8_t c, size_t n);

// Compares bytes in address ranges [s1,s1+n) and [s2,s2+n) and returns true iff
// the ranges are the same. This is similar to bcmp() but is optimized for the
// case that s1, s2 and n are all aligned by 8. Performance may degrade
// significantly for all other cases.
bool MemEq(const void* s1, const void* s2, size_t n);

// Returns true iff all n bytes at src address equal to byte value c.
// This is optimized for the case that src and n are both aligned by 8.
// Performance may degrade significantly for all other cases.
bool MemAllEqualTo(const void* src, uint8_t c, size_t n);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_MEM_UTIL_H_
