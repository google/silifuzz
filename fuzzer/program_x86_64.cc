// Copyright 2023 The Silifuzz Authors.
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

#include "absl/log/check.h"
#include "./fuzzer/program.h"
#include "./fuzzer/program_arch.h"  // IWYU pragma: keep
#include "./instruction/xed_util.h"
#include "./util/arch.h"

extern "C" {
#include "third_party/libxed/xed-interface.h"
}

namespace silifuzz {

namespace {

// Filter out problematic instructions.
bool AcceptInstruction(const xed_decoded_inst_t& xedd) {
  // TODO(ncbray): filter with xed_decoded_inst_valid_for_chip or
  // xed_decoded_inst_set_input_chip?
  return InstructionIsDeterministicInRunner(xedd) &&
         InstructionCanRunInUserSpace(xedd) &&
         !InstructionRequiresIOPrivileges(xedd);
}

InstructionDisplacementInfo GetDirectBranchInfo(
    const xed_decoded_inst_t& xedd, int64_t displacement_fixup_limit) {
  InstructionDisplacementInfo info{};
  if (xed_decoded_inst_get_branch_displacement_width(&xedd) > 0) {
    // Arch-specific displacements are relative to the end of the instruction.
    int64_t displacement = xed_decoded_inst_get_branch_displacement(&xedd) +
                           xed_decoded_inst_get_length(&xedd);
    if (DisplacementWithinFixupLimit(displacement, displacement_fixup_limit)) {
      info.encoded_byte_displacement = displacement;
    }
    // The instruction index will be resolved later.
  }
  return info;
}

void ReencodeInternal(const xed_state_t& dstate, Instruction<X86_64>& insn) {
  xed_decoded_inst_t xedd;

  xed_decoded_inst_zero_set_mode(&xedd, &dstate);

  CHECK_EQ(xed_decode(&xedd, insn.encoded.data(), insn.encoded.size()),
           XED_ERROR_NONE);
  // Check we consumed everything.
  CHECK_EQ(xed_decoded_inst_get_length(&xedd), insn.encoded.size());

  uint64_t displacement_width =
      xed_decoded_inst_get_branch_displacement_width(&xedd);

  // Check this is actually a direct branch.
  CHECK_GT(displacement_width, 0);

  // Arch-specific displacements are relative to the end of the instruction.
  int64_t new_displacement = insn.direct_branch.encoded_byte_displacement -
                             xed_decoded_inst_get_length(&xedd);

  // Prepare for encode.
  xed_encoder_request_init_from_decode(&xedd);

  // Modify the branch displacement.
  xed_decoded_inst_set_branch_displacement(&xedd, new_displacement,
                                           displacement_width);

  // Encode.
  InstructionByteBuffer<X86_64> ibuf;
  unsigned int actual_len = 0;
  xed_error_enum_t res = xed_encode(&xedd, ibuf, sizeof(ibuf), &actual_len);

  // We have not seen any errors when re-encoding an instruction, including
  // when the displacement is out of range.
  CHECK_EQ(res, XED_ERROR_NONE);

  // Copy the new encoding.
  insn.encoded.Copy(ibuf, actual_len);

  // Note: if the requested displacement was outside the range that could be
  // encoded, the encoded instruction will have an unexpected displacement at
  // this point.
}

}  // namespace

template <>
void ArchSpecificInit<X86_64>() {
  InitXedIfNeeded();
}

template <>
bool InstructionFromBytes(const uint8_t* bytes, size_t num_bytes,
                          Instruction<X86_64>& instruction,
                          const InstructionConfig& config,
                          bool must_decode_everything) {
  // On decode failure, we want the length to be zero.
  instruction.encoded.Clear();

  xed_decoded_inst_t xedd;

  xed_decoded_inst_zero(&xedd);
  xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LONG_64,
                            XED_ADDRESS_WIDTH_64b);

  // Did it decode?
  // Note: if xed cannot decode the instruction, we don't know what length it
  // is. There's no great way to support config.require_valid_encoding.
  if (xed_decode(&xedd, bytes, num_bytes) != XED_ERROR_NONE) return false;
  size_t decoded_length = xed_decoded_inst_get_length(&xedd);

  // The instruction data.
  // If the instruction decodes, we want the length to be correct even if a
  // later filter rejects it. This allows a test input to be decoded in a
  // "forgiving" way - the RIP can be advanced by the correct amount even when
  // decoding instructions we can't handle.
  instruction.encoded.Copy(bytes, decoded_length);
  instruction.direct_branch =
      GetDirectBranchInfo(xedd, config.displacement_fixup_limit);

  // Did we expect to consume every byte?
  if (must_decode_everything && decoded_length != num_bytes) return false;

  // Does it look like an instruction we can use?
  if (config.filter) {
    if (!AcceptInstruction(xedd)) return false;
  }

  return true;
}

template <>
bool TryToReencodeInstructionDisplacements(Instruction<X86_64>& insn) {
  CHECK(insn.direct_branch.valid());

  xed_state_t dstate;
  xed_state_init2(&dstate, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  // Re-encoding the instruction can canonicalize it.
  // Canonicalizing the instruction can change its size.
  // Changing its size can change shift where a displacement points to.
  // So if re-encoding the instruction canonicalizes it, we need to update the
  // displacement values and try again to guarantee either the encoded
  // displacement is what was requested, or that we're certain what was
  // requested was impossible.
  size_t original_size = insn.encoded.size();
  ReencodeInternal(dstate, insn);
  size_t canonical_size = insn.encoded.size();
  if (original_size != canonical_size) {
    // The displacement shifted when the instruction size changed, so re-encode
    // the instruction again.
    ReencodeInternal(dstate, insn);
    // The size of a canonical instruction should not change.
    CHECK_EQ(insn.encoded.size(), canonical_size);
  }

  // Check the encoded instruction is what we expect.
  xed_decoded_inst_t xedd;
  xed_decoded_inst_zero_set_mode(&xedd, &dstate);
  CHECK_EQ(xed_decode(&xedd, insn.encoded.data(), insn.encoded.size()),
           XED_ERROR_NONE);
  CHECK_EQ(xed_decoded_inst_get_length(&xedd), insn.encoded.size());

  // XED appears to truncate out-of-range displacements rather than failing to
  // encode.
  // We could do explicit range checks if we want to skip re-decoding the
  // instruction, but for now we're being cautious.
  if (xed_decoded_inst_get_branch_displacement(&xedd) +
          xed_decoded_inst_get_length(&xedd) !=
      insn.direct_branch.encoded_byte_displacement)
    return false;

  return true;
}

}  // namespace silifuzz
