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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_ARCH_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_ARCH_H_

namespace silifuzz {

struct X86_64 {};
struct AArch64 {};

#if defined(__x86_64__)
using Host = X86_64;
#elif defined(__aarch64__)
using Host = AArch64;
#else
#error "Unsupported architecture"
#endif

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_ARCH_H_
