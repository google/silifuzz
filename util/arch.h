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

// Arch::type_tag is a value that should be distinct for each Arch, allowing the
// type to be turned into a value when needed.
// By convention these values match Snapshot::Architecture::* so that it can be
// easily converted to that enum.
// Note that zero is not used as a type tag to make it easier to detect
// uninitialized values.

struct X86_64 {
  // Should be equal to Snapshot::Architecture::kX86_64
  static constexpr int type_tag = 1;
};

struct AArch64 {
  // Should be equal to Snapshot::Architecture::kAArch64
  static constexpr int type_tag = 2;
};

#if defined(__x86_64__)
using Host = X86_64;
#elif defined(__aarch64__)
using Host = AArch64;
#else
#error "Unsupported architecture"
#endif

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_ARCH_H_
