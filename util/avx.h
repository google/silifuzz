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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_AVX_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_AVX_H_
// Utilities dealing with AVX/AVX2/AVX-512 extension
#ifdef __x86_64__

namespace silifuzz {

// Returns true iff AVX-512 foundation instruction set is supported and
// registers zmm0-zmm31 and k0-k7 are accessible.
//
// This is in "C" namespace as this is called from assembly and it is easier to
// do so without function name mangling.
extern "C" bool HasAVX512Registers();

// Clears AVX-512 registers zmm16 to zmm31 and also opmask registers k0 to k7.
// This is part of AVX-512 state that can only be cleared using AVX-512F. The
// lower 16 AVX registers can be cleared using AVX instruction vzeroupper.
//
// REQUIRES: HasAVX512Registers() returns true.
//
// This cannot be called from C++ code. The x86_64 ABI specifies all AVX
// registers as caller-saved. A C++ caller saves all live AVX registers before
// calling this and restores those registers after call.
//
// This is in "C" namespace like HasAVX512Registers() above.
extern "C" void ClearAVX512OnlyState();

}  // namespace silifuzz

#endif  // __x86_64__
#endif  // THIRD_PARTY_SILIFUZZ_UTIL_AVX_H_
