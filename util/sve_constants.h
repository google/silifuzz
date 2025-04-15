// Copyright 2025 The SiliFuzz Authors.
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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_SVE_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_SVE_H_

#include <cstddef>

namespace silifuzz {

// SVE hardware has z0-z31 (vector), p0-p15 (predicate), and ffr (first fault
// register).
inline constexpr size_t kSveNumZReg = 32;
inline constexpr size_t kSveNumPReg = 16;

// The SVE Z registers have a max size of 256 bytes (2048 bits).
inline constexpr size_t kSveZRegMaxSizeBytes = 256;
// The SVE Z registers have a size alignment of 16 bytes (128 bits).
inline constexpr size_t kSveZRegSizeAlignmentBytes = 16;
// The SVE P registers are fixed to 1/8th the size of the Z registers.
inline constexpr size_t kSvePRegSizeZRegFactor = 8;
// The SVE P registers have a max size of 32 bytes (256 bits).
inline constexpr size_t kSvePRegMaxSizeBytes =
    kSveZRegMaxSizeBytes / kSvePRegSizeZRegFactor;
// The SVE P registers have a size alignment of 2 bytes (16 bits).
inline constexpr size_t kSvePRegSizeAlignmentBytes =
    kSveZRegSizeAlignmentBytes / kSvePRegSizeZRegFactor;

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_SVE_H_
