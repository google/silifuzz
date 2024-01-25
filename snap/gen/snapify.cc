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

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "./common/mapped_memory_map.h"
#include "./common/memory_perms.h"
#include "./common/memory_state.h"
#include "./common/snapshot.h"
#include "./snap/exit_sequence.h"
#include "./snap/gen/repeating_byte_runs.h"
#include "./snap/gen/reserved_memory_mappings.h"
#include "./snap/gen/snap_generator.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/platform.h"

namespace silifuzz {

namespace {

// Picks an expected end state compatible with the given options.
absl::StatusOr<const Snapshot::EndState *> PickEndState(
    const Snapshot &snapshot, const SnapifyOptions &options) {
  if (options.allow_undefined_end_state) {
    if (snapshot.expected_end_states().size() != 1) {
      return absl::InvalidArgumentError(
          absl::StrCat("want exactly 1 undefined expected endstate, found ",
                       snapshot.expected_end_states().size()));
    }
    RETURN_IF_NOT_OK(snapshot.IsCompleteSomeState());
    return &snapshot.expected_end_states()[0];
  }

  // Must have an expected end state for the requested platform.
  for (const auto &es : snapshot.expected_end_states()) {
    if (es.has_platform(options.platform_id) ||
        options.platform_id == PlatformId::kAny) {
      RETURN_IF_NOT_OK(es.IsComplete());
      return &es;
    }
  }
  return absl::NotFoundError(absl::StrCat("no expected end state for platform ",
                                          EnumStr(options.platform_id)));
}

typedef bool (*CompressionQuery)(const MemoryState &memory_state,
                                 const Snapshot::MemoryBytes &bytes);

bool ShouldAlwaysCompress(const MemoryState &memory_state,
                          const Snapshot::MemoryBytes &bytes) {
  return true;
}

bool ShouldCompressNonExecutable(const MemoryState &memory_state,
                                 const Snapshot::MemoryBytes &bytes) {
  return !memory_state.mapped_memory()
              .PermsAt(bytes.start_address())
              .Has(MemoryPerms::kExecutable);
}

bool ShouldNeverCompress(const MemoryState &memory_state,
                         const Snapshot::MemoryBytes &bytes) {
  return false;
}

// Helper for Snapify(). This normalizes `memory_byte_list` and then
// breaks list elements into smaller MemoryBytes objects if necessary for
// run-length compression. Optionally apply run-length compression on byte data.
// Returns a status to report any errors.
absl::StatusOr<Snapshot::MemoryBytesList> SnapifyMemoryByteList(
    const MemoryState &memory_state, CompressionQuery should_compress) {
  // Normalize memory bytes to ensure all bytes in a MemoryBytes have identical
  // permissions
  Snapshot::MemoryBytesList memory_bytes_list =
      memory_state.memory_bytes_list(memory_state.written_memory());
  Snapshot::NormalizeMemoryBytes(memory_state.mapped_memory(),
                                 &memory_bytes_list);

  // Prepare the memory bytes for run length compression when it is appropriate.
  // We may chose not to compress some byte runs if we want to mmap the byte
  // data directly from the corpus.
  Snapshot::MemoryBytesList result;
  for (const auto &memory_bytes : memory_bytes_list) {
    if (should_compress(memory_state, memory_bytes)) {
      ASSIGN_OR_RETURN_IF_NOT_OK(Snapshot::MemoryBytesList runs,
                                 GetRepeatingByteRuns(memory_bytes));
      result.reserve(result.size() + runs.size());
      for (auto &run : runs) {
        result.push_back(std::move(run));
      }
    } else {
      result.push_back(std::move(memory_bytes));
    }
  }
  return result;
}

// Transforms the snapshot's MemoryBytes into Snap-compatible format.
// Specifically, ensures that all MemoryBytes are fragmented according to `opts`
// in both the Snapshot and all EndStates. Populates all EndStates with all
// writable bytes from the parent Snapshot.
absl::Status SnapifyMemoryBytes(Snapshot &snapshot,
                                const SnapifyOptions &opts) {
  MemoryState memory_state =
      MemoryState::MakeInitial(snapshot, MemoryState::kZeroMappedBytes);

  CompressionQuery should_compress_initial = &ShouldNeverCompress;
  if (opts.compress_repeating_bytes) {
    if (opts.support_direct_mmap) {
      should_compress_initial = &ShouldCompressNonExecutable;
    } else {
      should_compress_initial = &ShouldAlwaysCompress;
    }
  }

  ASSIGN_OR_RETURN_IF_NOT_OK(
      Snapshot::MemoryBytesList snapified_memory_bytes_list,
      SnapifyMemoryByteList(memory_state, should_compress_initial));
  RETURN_IF_NOT_OK(
      snapshot.ReplaceMemoryBytes(std::move(snapified_memory_bytes_list)));

  Snapshot::EndStateList end_states = snapshot.expected_end_states();
  snapshot.set_expected_end_states({});

  for (Snapshot::EndState &end_state : end_states) {
    if (end_state.IsComplete().ok()) {
      MemoryState memory_state =
          MemoryState::MakeInitial(snapshot, MemoryState::kZeroMappedBytes);
      // Apply deltas from the current end state.
      memory_state.SetMemoryBytes(end_state.memory_bytes());

      // Keep just the writable pages in memory_state.
      snapshot.mapped_memory_map().Iterate(
          [&memory_state](auto start, auto limit, MemoryPerms perms) {
            if (!perms.Has(MemoryPerms::kWritable)) {
              // Remove all non-writable mappings (and bytes) from the memory
              // state.
              memory_state.RemoveMemoryMapping(start, limit);
            }
          });
      ASSIGN_OR_RETURN_IF_NOT_OK(
          Snapshot::MemoryBytesList snapified_end_state_memory_bytes_list,
          SnapifyMemoryByteList(memory_state, opts.compress_repeating_bytes
                                                  ? &ShouldAlwaysCompress
                                                  : &ShouldNeverCompress));
      RETURN_IF_NOT_OK(end_state.ReplaceMemoryBytes(
          std::move(snapified_end_state_memory_bytes_list)));
    } else {
      DCHECK(opts.allow_undefined_end_state);
    }
    RETURN_IF_NOT_OK(snapshot.can_add_expected_end_state(end_state));
    snapshot.add_expected_end_state(end_state);
  }

  return absl::OkStatus();
}

// Overwrites any bytes at `address` with the Snap exit sequence. Does not
// add any new memory mappings.
// NOTE: this transformation likely invalidates any expected end states.
template <typename Arch>
absl::Status MergeExitSequence(Snapshot &snapshot, Snapshot::Address address) {
  // Add a snap exit sequence to initial memory bytes at the end point
  // instruction address.
  Snapshot::ByteData snap_exit_byte_data(GetSnapExitSequenceSize<Arch>(), 0);
  RETURN_IF_NOT_OK(
      Snapshot::MemoryBytes::CanConstruct(address, snap_exit_byte_data));
  WriteSnapExitSequence<Arch>(
      reinterpret_cast<uint8_t *>(snap_exit_byte_data.data()));
  Snapshot::MemoryBytes snap_exit_memory_bytes(address, snap_exit_byte_data);
  if (!snapshot.mapped_memory_map().Contains(
          snap_exit_memory_bytes.start_address(),
          snap_exit_memory_bytes.limit_address())) {
    return absl::InvalidArgumentError(
        "InsertExitSequence(): no room for the exit sequence");
  }
  // Construct initial memory state by copying the original.
  MemoryState memory_state =
      MemoryState::MakeInitial(snapshot, MemoryState::kZeroMappedBytes);
  // Overwrite bytes at `address` with the exit sequence.
  memory_state.SetMemoryBytes(snap_exit_memory_bytes);

  Snapshot::MemoryBytesList memory_bytes_list =
      memory_state.memory_bytes_list(memory_state.written_memory());
  RETURN_IF_NOT_OK(snapshot.ReplaceMemoryBytes(std::move(memory_bytes_list)));
  return absl::OkStatus();
}

}  // namespace

absl::Status CanSnapify(const Snapshot &snapshot, const SnapifyOptions &opts) {
  ASSIGN_OR_RETURN_IF_NOT_OK(const Snapshot::EndState *end_state,
                             PickEndState(snapshot, opts));
  // Must end at an instruction, not a signal.
  const Snapshot::Endpoint &endpoint = end_state->endpoint();
  if (endpoint.type() != Snapshot::Endpoint::kInstruction) {
    return absl::InvalidArgumentError("endpoint isn't kInstruction");
  }

  if (OverlapReservedMemoryMappings(snapshot.memory_mappings())) {
    if (VLOG_IS_ON(3)) {
      std::string mappings;
      for (const auto &mapping : snapshot.memory_mappings()) {
        absl::StrAppend(&mappings, mapping.DebugString(), ",");
      }
      VLOG_INFO(3,
                "memory mappings overlap reserved memory mappings: ", mappings);
    }
    return absl::InvalidArgumentError(
        "memory mappings overlap reserved memory mappings");
  }

  // There should be code space to append an exit sequence.
  const MappedMemoryMap &mapped_memory_map = snapshot.mapped_memory_map();
  const Snapshot::Address ending_rip = endpoint.instruction_address();
  const size_t exit_sequence_size =
      ARCH_DISPATCH(GetSnapExitSequenceSize, snapshot.architecture_id());
  if (!mapped_memory_map.Contains(ending_rip,
                                  ending_rip + exit_sequence_size)) {
    return absl::InvalidArgumentError(
        "CanSnapify: no room for the exit sequence");
  }

  // Skip the rest of checks if this is an undefined state. We don't know the
  // expected values of the registers so inspecting RSP is not possible.
  if (opts.allow_undefined_end_state &&
      end_state->IsComplete(Snapshot::kUndefinedEndState).ok()) {
    return absl::OkStatus();
  }

  // We need 8 bytes of stack to exit (the return address pushed by call)
  // Check that [rsp-8, rsp) is mapped. Also check that RSP=0 is handled.
  Snapshot::Address ending_rsp = snapshot.ExtractRsp(end_state->registers());
  if (ending_rsp < 8 ||
      !mapped_memory_map.Contains(ending_rsp - 8, ending_rsp)) {
    return absl::InvalidArgumentError("need at least 8 bytes on stack");
  }

  return absl::OkStatus();
}

absl::StatusOr<Snapshot> Snapify(const Snapshot &snapshot,
                                 const SnapifyOptions &opts) {
  RETURN_IF_NOT_OK(CanSnapify(snapshot, opts));

  ASSIGN_OR_RETURN_IF_NOT_OK(const Snapshot::EndState *end_state,
                             PickEndState(snapshot, opts));
  const Snapshot::Endpoint &endpoint = end_state->endpoint();

  Snapshot snapified = snapshot.Copy();

  // Make sure adjacent memory mappings are merged.
  snapified.NormalizeMemoryMappings();

  // Replace potentially multiple expected end states with just the one for the
  // requested platform.
  snapified.set_expected_end_states({*end_state});

  RETURN_IF_NOT_OK(ARCH_DISPATCH(MergeExitSequence, snapified.architecture_id(),
                                 snapified, endpoint.instruction_address()));

  RETURN_IF_NOT_OK(SnapifyMemoryBytes(snapified, opts));

  return snapified;
}

}  // namespace silifuzz
