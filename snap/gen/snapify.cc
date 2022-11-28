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

#include "./snap/gen/snap_generator.h"

#include "absl/status/statusor.h"
#include "./common/memory_state.h"
#include "./common/snapshot.h"
#include "./common/snapshot_util.h"
#include "./snap/exit_sequence.h"
#include "./snap/gen/repeating_byte_runs.h"
#include "./snap/gen/reserved_memory_mappings.h"
#include "./util/arch_mem.h"
#include "./util/itoa.h"
#include "./util/ucontext/ucontext.h"

namespace silifuzz {

namespace {

// Picks an expected end state compatible with the given options.
absl::StatusOr<const Snapshot::EndState *> PickEndState(
    const Snapshot &snapshot, const SnapifyOptions &options) {
  if (options.allow_undefined_end_state) {
    if (snapshot.expected_end_states().size() != 1) {
      return absl::InvalidArgumentError(
          absl::StrCat("want exactly 1 endstate, found ",
                       snapshot.expected_end_states().size()));
    }
    RETURN_IF_NOT_OK(snapshot.IsCompleteSomeState());
    return &snapshot.expected_end_states()[0];
  } else {
    // Must have an expected end state for the requested platform.
    for (const auto &es : snapshot.expected_end_states()) {
      if (es.has_platform(options.platform_id) ||
          options.platform_id == PlatformId::kAny) {
        RETURN_IF_NOT_OK(es.IsComplete());
        return &es;
      }
    }
    return absl::InvalidArgumentError(absl::StrCat(
        "no expected end state for platform ", EnumStr(options.platform_id)));
  }
}

absl::Status CanConvert(const Snapshot &snapshot, const SnapifyOptions &opts) {
  absl::StatusOr<const Snapshot::EndState *> end_state_or =
      PickEndState(snapshot, opts);
  RETURN_IF_NOT_OK(end_state_or.status());
  const Snapshot::EndState &end_state = *end_state_or.value();
  // Must end at an instruction, not a signal.
  const Snapshot::Endpoint &endpoint = end_state.endpoint();
  if (endpoint.type() != Snapshot::Endpoint::kInstruction) {
    return absl::InvalidArgumentError("endpoint isn't kInstruction");
  }

  if (OverlapReservedMemoryMappings(snapshot.memory_mappings())) {
    return absl::InvalidArgumentError(
        "memory mappings overlap reserved memory mappings");
  }

  // There should be code space to append an exit sequence.
  const MappedMemoryMap &mapped_memory_map = snapshot.mapped_memory_map();
  const Snapshot::Address ending_rip = endpoint.instruction_address();
  if (!mapped_memory_map.Contains(ending_rip,
                                  ending_rip + kSnapExitSequenceSize)) {
    return absl::InvalidArgumentError(
        "CanConvert: no room for the exit sequence");
  }

  // Skip the rest of checks if this is an undefined state. We don't know the
  // expected values of the registers so inspecting RSP is not possible.
  if (opts.allow_undefined_end_state &&
      end_state.IsComplete(Snapshot::kUndefinedEndState).ok()) {
    return absl::OkStatus();
  }

  // We need 8 bytes of stack to exit (the return address pushed by call)
  // Check that [rsp-8, rsp) is mapped. Also check that RSP=0 is handled.
  Snapshot::Address ending_rsp = snapshot.ExtractRsp(end_state.registers());
  if (ending_rsp < 8 ||
      !mapped_memory_map.Contains(ending_rsp - 8, ending_rsp)) {
    return absl::InvalidArgumentError("need at least 8 bytes on stack");
  }

  return absl::OkStatus();
}

// Helper for Snapify(). This normalizes `memory_byte_list` and then
// breaks list elements into smaller MemoryBytes objects if necessary for
// run-length compression. Optionally apply run-length compression on byte data.
// Returns a status to report any errors.
absl::Status SnapifyMemoryByteList(
    const MappedMemoryMap &memory_map, const SnapifyOptions &opts,
    Snapshot::MemoryBytesList *memory_byte_list) {
  // Normalize memory bytes to ensure all bytes in a MemoryBytes have identical
  // permissions
  Snapshot::NormalizeMemoryBytes(memory_map, memory_byte_list);

  // Prepare memory byte list for run-length compression.
  if (opts.compress_repeating_bytes) {
    ASSIGN_OR_RETURN_IF_NOT_OK(Snapshot::MemoryBytesList runs,
                               GetRepeatingByteRuns(*memory_byte_list));
    memory_byte_list->swap(runs);
  }

  return absl::OkStatus();
}

template <typename Arch>
static Snapshot::MemoryBytes RestoreUContextStackBytesImpl(
    const Snapshot &snapshot) {
  GRegSet<Arch> gregs;
  CHECK_STATUS(ConvertRegsFromSnapshot(snapshot.registers(), &gregs));
  std::string stack_data = RestoreUContextStackBytes(gregs);
  return Snapshot::MemoryBytes(GetStackPointer(gregs) - stack_data.size(),
                               stack_data);
}

// The bytes that RestoreUContext() will write into the stack of the
// snapshot as a (presently unavoidable) part of doing its work
// when jumping-in to start executing `snapshot`.
static Snapshot::MemoryBytes RestoreUContextStackBytes(
    const Snapshot &snapshot) {
  switch (snapshot.architecture()) {
    case Snapshot::Architecture::kX86_64:
      return RestoreUContextStackBytesImpl<X86_64>(snapshot);
    case Snapshot::Architecture::kAArch64:
      return RestoreUContextStackBytesImpl<AArch64>(snapshot);
    default:
      LOG_FATAL("Unexpected architecture: ", snapshot.architecture());
  }
}

}  // namespace

absl::StatusOr<Snapshot> Snapify(const Snapshot &snapshot,
                                 const SnapifyOptions &opts) {
  RETURN_IF_NOT_OK(CanConvert(snapshot, opts));
  // Copy Id and Architecture.
  Snapshot snapified(snapshot.architecture(), snapshot.id());
  snapified.set_metadata(snapshot.metadata());

  // Copy memory mappings and optionally force mapping to be writable if
  // requested in options.
  for (const auto &memory_mapping : snapshot.memory_mappings()) {
    RETURN_IF_NOT_OK(Snapshot::MemoryMapping::CanMakeSized(
        memory_mapping.start_address(), memory_mapping.num_bytes()));
    Snapshot::MemoryMapping snapfied_memory_mapping =
        Snapshot::MemoryMapping::MakeSized(memory_mapping.start_address(),
                                           memory_mapping.num_bytes(),
                                           memory_mapping.perms());
    RETURN_IF_NOT_OK(snapified.can_add_memory_mapping(snapfied_memory_mapping));
    snapified.add_memory_mapping(snapfied_memory_mapping);
  }

  // Copy registers. This must be done after setting memory mappings as
  // program counter must point to a valid executable address.
  snapified.set_registers(snapshot.registers());

  // Construct initial memory state of the snapified snaphsot.
  MemoryState memory_state =
      MemoryState::MakeInitial(snapshot, MemoryState::kZeroMappedBytes);

  // Add a snap exit sequence to initial memory bytes at the end point
  // instruction address.
  Snapshot::ByteData snap_exit_byte_data(kSnapExitSequenceSize, 0);
  WriteSnapExitSequence(
      reinterpret_cast<uint8_t *>(snap_exit_byte_data.data()));

  absl::StatusOr<const Snapshot::EndState *> end_state_or =
      PickEndState(snapshot, opts);
  RETURN_IF_NOT_OK(end_state_or.status());
  const Snapshot::EndState &end_state = *end_state_or.value();
  const Snapshot::Endpoint &endpoint = end_state.endpoint();
  RETURN_IF_NOT_OK(Snapshot::MemoryBytes::CanConstruct(
      endpoint.instruction_address(), snap_exit_byte_data));
  Snapshot::MemoryBytes snap_exit_memory_bytes(endpoint.instruction_address(),
                                               snap_exit_byte_data);

  // We need to make sure that this does not overwrite code that a snapshot
  // cares about. In theory, a snapshot can read memory in the region we
  // write the exit sequence so that the snapshot can end differently depending
  // on where the exit sequence is present or not. Right now there is no easy
  // way to detect this. We can run the resultant Snap to filter out these
  // cases.
  //
  // A different but related problem is that some snapshot ends with instruction
  // prefixes, which affect the first instruction of the exit sequence. We tried
  // patching different NOPs in the front of the exit sequence but could not
  // find a NOP instruction variant that is immune to all prefixes. We may look
  // at the byte before the ending instruction address and see if that matches
  // one of the instruction prefixes but doing that may over estimate the
  // issue and filter out more snapshots than necessary.
  if (!memory_state.mapped_memory().Contains(
          snap_exit_memory_bytes.start_address(),
          snap_exit_memory_bytes.limit_address())) {
    return absl::InvalidArgumentError("Snapify: no room for the exit sequence");
  }
  memory_state.SetMemoryBytes(snap_exit_memory_bytes);

  Snapshot::MemoryBytesList initial_memory_bytes_list =
      memory_state.memory_bytes_list(memory_state.written_memory());
  RETURN_IF_NOT_OK(SnapifyMemoryByteList(snapified.mapped_memory_map(), opts,
                                         &initial_memory_bytes_list));
  for (const auto &memory_bytes : initial_memory_bytes_list) {
    RETURN_IF_NOT_OK(snapified.can_add_memory_bytes(memory_bytes));
    snapified.add_memory_bytes(memory_bytes);
  }

  // Add RestoreUContext stack bytes, original end state memory delta, and
  // snap exit stack bytes to construct full end state memory bytes.
  memory_state.SetMemoryBytes(RestoreUContextStackBytes(snapshot));
  memory_state.SetMemoryBytes(end_state.memory_bytes());

  // Additionally check that endpoint is kInstruction because the fixup needs
  // to be applied only for this type of endpoints.
  CHECK(endpoint.type() == Snapshot::Endpoint::kInstruction);
  Snapshot::RegisterState snapified_end_state_regs = end_state.registers();

  // Construct a snapified end state from the original.
  Snapshot::EndState snapified_end_state(endpoint, snapified_end_state_regs);
  snapified_end_state.set_platforms(end_state.platforms());

  if (end_state.IsComplete().ok()) {
    // Apply the memory mappings and the exit sequence fixup only when we have
    // a normal endstate.
    // The snap exit sequence written above consists of a call instruction
    // followed by a 64-bit address. The length of an exit sequence is thus the
    // length of a call instruction plus 8 bytes. When the exit call is
    // executed, it leaves the address after the call instruction on stack.
    constexpr size_t kCallInsnSize = kSnapExitSequenceSize - sizeof(uint64_t);
    Snapshot::Address return_address =
        endpoint.instruction_address() + kCallInsnSize;
    Snapshot::ByteData return_address_byte_data(
        reinterpret_cast<Snapshot::ByteData::value_type *>(&return_address),
        sizeof(return_address));
    // On x86_64, a stack push is done by decrementing the stack point first
    // and then writing to location pointed to by the new stack pointer.
    //
    // before call
    //   RSP-> 20000000: XX XX ....
    //         1ffffff8: XX XX ....
    //
    // after call
    //         20000000: XX XX ....
    //   RSP-> 1ffffff8: <return address>
    //
    const Snapshot::Address end_point_stack_pointer =
        snapshot.ExtractRsp(end_state.registers());
    RETURN_IF_NOT_OK(Snapshot::MemoryBytes::CanConstruct(
        end_point_stack_pointer - sizeof(return_address),
        return_address_byte_data));
    Snapshot::MemoryBytes return_address_memory_bytes(
        end_point_stack_pointer - sizeof(return_address),
        return_address_byte_data);
    memory_state.SetMemoryBytes(return_address_memory_bytes);
    Snapshot::MemoryBytesList end_state_memory_bytes_list =
        memory_state.memory_bytes_list(memory_state.written_memory());
    RETURN_IF_NOT_OK(SnapifyMemoryByteList(snapified.mapped_memory_map(), opts,
                                           &end_state_memory_bytes_list));
    for (const auto &memory_bytes : end_state_memory_bytes_list) {
      // Include only writable memory in the endstate.
      if (snapified.mapped_memory_map()
              .Perms(memory_bytes.start_address(), memory_bytes.limit_address(),
                     MemoryPerms::kOr)
              .Has(MemoryPerms::kWritable)) {
        RETURN_IF_NOT_OK(
            snapified_end_state.can_add_memory_bytes(memory_bytes));
        snapified_end_state.add_memory_bytes(memory_bytes);
      }
    }
  } else {
    // Ensure that an undefined endstate is expected.
    DCHECK(opts.allow_undefined_end_state);
  }
  RETURN_IF_NOT_OK(snapified.can_add_expected_end_state(snapified_end_state));
  snapified.add_expected_end_state(snapified_end_state);

  return snapified;
}

}  // namespace silifuzz
