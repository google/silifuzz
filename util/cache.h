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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_CACHE_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_CACHE_H_

#include <cstddef>

namespace silifuzz {

// Ensure memory in the range [begin, end) has been flushed from the dcache
// and invalidated in the icache. This ensures any attempt to execute
// instructions in this range will see the latest version of the data.
// This is required if code is dynamically loaded or generated on aarch64.
// x86_64 automatically maintains coherency between the dcache and the icache so
// this operation should be a no-op.
// 'begin' and 'end' do not need to be aligned to cache line granularity. This
// function will sync all the cache lines that cover the range, effectively
// rounding 'begin' down and 'end' up as needed.
template <typename T>
inline void sync_instruction_cache(T* begin, T* end) {
  __builtin___clear_cache(reinterpret_cast<char*>(begin),
                          reinterpret_cast<char*>(end));
}

template <typename T>
inline void sync_instruction_cache(T* begin, size_t size) {
  sync_instruction_cache(reinterpret_cast<char*>(begin),
                         reinterpret_cast<char*>(begin) + size);
}

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_CACHE_H_
