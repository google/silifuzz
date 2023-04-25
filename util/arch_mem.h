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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_ARCH_MEM_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_ARCH_MEM_H_

#include <stddef.h>

#include <string>

#include "./util/arch.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {

// Pad `code` with architecture-specific trap instructions until `code` is
// exactly `target_size` bytes long.
// `target_size` - `code`.size() must not be negative and must also be a
// multiple of the trap instruction size.
template <typename Arch>
void PadToSizeWithTraps(std::string& code, size_t target_size);

// Returns the bytes that RestoreUContext() writes on the stack of the context
// it is jumping into. These bytes may depend on the GRegSet of the context it
// is jumping into. These bytes are immediately below the stack pointer and
// will be overwritten by any subsequent "push" instructions.
template <typename Arch>
std::string RestoreUContextStackBytes(const GRegSet<Arch>& gregs);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_ARCH_MEM_H_
