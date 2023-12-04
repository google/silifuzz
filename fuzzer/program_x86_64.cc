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

#include "./fuzzer/program.h"
#include "./instruction/xed_util.h"

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

}  // namespace

void ArchSpecificInit() { InitXedIfNeeded(); }

bool InstructionFromBytes(const uint8_t* bytes, size_t num_bytes,
                          Instruction& instruction,
                          bool must_decode_everything) {
  // On decode failure, we want the length to be zero.
  instruction.encoded.Clear();

  xed_decoded_inst_t xedd;

  xed_decoded_inst_zero(&xedd);
  xed_decoded_inst_set_mode(&xedd, XED_MACHINE_MODE_LONG_64,
                            XED_ADDRESS_WIDTH_64b);

  // Did it decode?
  if (xed_decode(&xedd, bytes, num_bytes) != XED_ERROR_NONE) return false;
  size_t decoded_length = xed_decoded_inst_get_length(&xedd);

  // The instruction data.
  // If the instruction decodes, we want the length to be correct even if a
  // later filter rejects it. This allows a test input to be decoded in a
  // "forgiving" way - the RIP can be advanced by the correct amount even when
  // decoding instructions we can't handle.
  instruction.encoded.Copy(bytes, decoded_length);

  // Did we expect to consume every byte?
  if (must_decode_everything && decoded_length != num_bytes) return false;

  // Does it look like an instruction we can use?
  if (!AcceptInstruction(xedd)) return false;

  return true;
}

}  // namespace silifuzz
