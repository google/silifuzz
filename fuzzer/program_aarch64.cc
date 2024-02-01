// Copyright 2024 The Silifuzz Authors.
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

#include <cstddef>
#include <cstdint>

#include "absl/strings/string_view.h"
#include "./fuzzer/program.h"
#include "./fuzzer/program_arch.h"  // IWYU pragma: keep
#include "./instruction/static_insn_filter.h"
#include "./util/arch.h"

namespace silifuzz {

template <>
void ArchSpecificInit<AArch64>() {}

template <>
bool InstructionFromBytes(const uint8_t* bytes, size_t num_bytes,
                          Instruction<AArch64>& instruction,
                          bool must_decode_everything) {
  // On decode failure, we want the length to be zero.
  instruction.encoded.Clear();

  if (num_bytes < 4) {
    return false;
  }

  // TODO(ncbray): actually disassemble the instruction.

  // The instruction data.
  // If the instruction decodes, we want the length to be correct even if a
  // later filter rejects it. This lets higher-level code skip the bytes.
  instruction.encoded.Copy(bytes, 4);

  // TODO(ncbray): derive displacement info.
  instruction.direct_branch = {};

  // Did we expect to consume every byte?
  if (must_decode_everything && 4 != num_bytes) return false;

  // Does it look like an instruction we can use?
  absl::string_view view(
      reinterpret_cast<const char*>(instruction.encoded.begin()),
      reinterpret_cast<const char*>(instruction.encoded.end()));
  if (!StaticInstructionFilter<AArch64>(view)) return false;

  return true;
}

template <>
bool TryToReencodeInstructionDisplacements(Instruction<AArch64>& insn) {
  // TODO(ncbray): implement once we actually derive displacement info.
  return true;
}

}  // namespace silifuzz
