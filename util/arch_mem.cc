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

#include "./util/arch_mem.h"

#include "./util/checks.h"

namespace silifuzz {

template <>
void PadToSizeWithTraps<X86_64>(std::string& code, size_t target_size) {
  CHECK_LE(code.size(), target_size);
  code.resize(target_size, 0xcc);
}

template <>
void PadToSizeWithTraps<AArch64>(std::string& code, size_t target_size) {
  CHECK_LE(code.size(), target_size);
  CHECK_EQ(code.size() % 4, 0);
  CHECK_EQ(target_size % 4, 0);
  code.resize(target_size, 0);
}

template <>
std::string RestoreUContextStackBytes(const GRegSet<X86_64>& gregs) {
  std::string stack_bytes;
  stack_bytes.append(reinterpret_cast<const char*>(&gregs.eflags), 8);
  stack_bytes.append(reinterpret_cast<const char*>(&gregs.rip), 8);
  return stack_bytes;
}

template <>
std::string RestoreUContextStackBytes(const GRegSet<AArch64>& gregs) {
  std::string stack_bytes;
  // aarch64 RestoreUContext currently zeros out the memory it uses
  stack_bytes.append(8, 0);
  return stack_bytes;
}

}  // namespace silifuzz
