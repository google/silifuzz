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

#include <utility>

#include "./util/checks.h"

namespace silifuzz {

// By convention these values match Snapshot::Architecture::* so that it can be
// easily converted to that enum.
// Note that zero is an invalid architecture to make it easier to detect
// uninitialized values.

enum class ArchitectureId {
  kUndefined = 0,
  kX86_64 = 1,
  kAArch64 = 2,
};

struct X86_64 {
  static constexpr ArchitectureId architecture_id = ArchitectureId::kX86_64;
  static constexpr const char* arch_name = "x86_64";
};

struct AArch64 {
  static constexpr ArchitectureId architecture_id = ArchitectureId::kAArch64;
  static constexpr const char* arch_name = "aarch64";
};

#define ALL_ARCH_TYPES X86_64, AArch64

#if defined(__x86_64__)
using Host = X86_64;
#elif defined(__aarch64__)
using Host = AArch64;
#else
#error "Unsupported architecture"
#endif

#define ARCH_DISPATCH(func, arch, ...)                                         \
  [&](silifuzz::ArchitectureId arch_id, auto&&... args) {                      \
    switch (arch_id) {                                                         \
      case silifuzz::ArchitectureId::kX86_64:                                  \
        return func<silifuzz::X86_64>(std::forward<decltype(args)>(args)...);  \
      case silifuzz::ArchitectureId::kAArch64:                                 \
        return func<silifuzz::AArch64>(std::forward<decltype(args)>(args)...); \
      default:                                                                 \
        LOG_FATAL("Unsupported architecture");                                 \
    }                                                                          \
  }(arch, ##__VA_ARGS__)

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_ARCH_H_
