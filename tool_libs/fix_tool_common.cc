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

#include "./tool_libs/fix_tool_common.h"

#include <cstdint>
#include <iterator>
#include <memory>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./common/snapshot.h"
#include "./common/snapshot_enums.h"
#include "./common/snapshot_util.h"
#include "./runner/runner_provider.h"
#include "./runner/snap_maker.h"
#include "./util/hostname.h"
#include "./util/platform.h"

namespace silifuzz {
namespace fix_tool_internal {
namespace {

snapshot_types::Address PageAddress(snapshot_types::Address addr,
                                    uint64_t page_size) {
  return (addr / page_size) * page_size;
}

// Runs `snapshot` through the maker to construct end state. Also verify
// the remade snapshot to filter out any problematic snapshot.
// If `x86_filter_split_lock` is true, any x86 snapshot with a locking
// instruction that accesses memory across a cache line boundary is rejected.
// Returns the remade snapshot or an error status.
absl::StatusOr<Snapshot> RemakeAndVerify(const Snapshot& snapshot,
                                         bool x86_filter_split_lock) {
  SnapMaker::Options opts;
  opts.runner_path = RunnerLocation();
  opts.x86_filter_split_lock = x86_filter_split_lock;
  SnapMaker maker = SnapMaker(opts);
  absl::StatusOr<Snapshot> made_snapshot_or = maker.Make(snapshot);
  RETURN_IF_NOT_OK(made_snapshot_or.status());
  absl::StatusOr<Snapshot> recorded_snapshot =
      maker.RecordEndState(*made_snapshot_or);
  RETURN_IF_NOT_OK(recorded_snapshot.status());

  const Snapshot::Endpoint& ep =
      recorded_snapshot->expected_end_states()[0].endpoint();
  if (ep.type() != snapshot_types::Endpoint::kInstruction) {
    return absl::InternalError(absl::StrCat(
        "Cannot fix ", EnumStr(ep.sig_cause()), "/", EnumStr(ep.sig_num())));
  }
  if (absl::Status verify_status = maker.Verify(*recorded_snapshot);
      !verify_status.ok()) {
    return verify_status;
  }

  return recorded_snapshot;
}

}  // namespace

bool NormalizeSnapshot(Snapshot& snapshot, FixToolCounters* counters) {
  // If there's a single end state keep it
  bool has_one_endstate = snapshot.expected_end_states().size() == 1 &&
                          snapshot.IsCompleteSomeState().ok();
  if (!has_one_endstate) {
    // Otherwise, replace all expected end states with a single undefined.
    // TODO(ksteuck): [as-needed] Apply this to fuzzed snapshots only.
    const uint64_t kPageSizeBytes = snapshot.page_size();
    Snapshot::Address orig_endpoint_address =
        snapshot.ExtractRip(snapshot.registers());
    // "Imagine" an endpoint at the end of the code page. 15 bytes is the
    // padding for the exit V2 sequence.
    orig_endpoint_address = PageAddress(orig_endpoint_address, kPageSizeBytes) +
                            kPageSizeBytes - 15;
    Snapshot::EndState undef_end_state =
        Snapshot::EndState(Snapshot::Endpoint(orig_endpoint_address));
    snapshot.set_expected_end_states({});
    snapshot.set_negative_memory_mappings({});
    if (auto status = snapshot.can_add_expected_end_state(undef_end_state);
        !status.ok()) {
      counters->Increment(
          absl::StrCat("silifuzz-ERROR-AddUndefEndState:", status.message()));
      return false;
    }
    snapshot.add_expected_end_state(undef_end_state);
    counters->Increment("silifuzz-INFO-UndefEndStateAdded");
  }
  snapshot.NormalizeAll();
  return true;
}

bool RewriteInitialState(Snapshot& snapshot, FixToolCounters* counters) {
  GRegSet gregs;
  FPRegSet fpregs;
  CHECK_STATUS(ConvertRegsFromSnapshot(snapshot.registers(), &gregs, &fpregs));

  // Non-zero initialization of at least 1 XMM register inhibits init state
  // optimization on Arcadia. This is a workaround for erratum 1386 "XSAVES
  // Instruction May Fail to Save XMM Registers to the Provided State Save
  // Area". See https://www.amd.com/system/files/TechDocs/56683-PUB-1.07.pdf
  bool changed = false;
  bool all_zeroes = true;
  for (const __uint128_t* it = std::begin(fpregs.xmm);
       it != std::end(fpregs.xmm); ++it) {
    if (*it != 0) {
      all_zeroes = false;
      break;
    }
  }

  if (all_zeroes) {
    fpregs.xmm[0] = 0xdeadbeefu;
    changed = true;
  }

  if (changed) {
    Snapshot::RegisterState regs = ConvertRegsToSnapshot(gregs, fpregs);
    if (snapshot.can_set_registers(regs).ok()) {
      snapshot.set_registers(regs);
    } else {
      counters->Increment("silifuzz-ERROR-Rewrite-cannot-set-registers");
    }
    counters->Increment("silifuzz-INFO-Rewrite-changed");
  }
  return changed;
}

absl::StatusOr<Snapshot> FixupSnapshot(const Snapshot& input,
                                       PlatformFixToolCounters* counters,
                                       bool x86_filter_split_lock) {
  absl::StatusOr<Snapshot> remade_snapshot_or =
      RemakeAndVerify(input, x86_filter_split_lock);
  if (!remade_snapshot_or.ok()) {
    counters->IncCounter("ERROR-Make:", remade_snapshot_or.status().message());
    return remade_snapshot_or.status();
  }

  int num_end_states = remade_snapshot_or->expected_end_states().size();
  if (num_end_states > 1) {
    counters->IncCounter("ERROR-multi-state-test:", num_end_states);
    return absl::InternalError("multi-state-test");
  }

  if (num_end_states == 0) {
    counters->IncCounter("ERROR-zero-end-states-test:", num_end_states);
    return absl::InternalError("zero-end-states-test");
  }
  // Sanity check the only expected end state -- it must have the current
  // platform.
  if (!remade_snapshot_or->expected_end_states()[0].has_platform(
          CurrentPlatformId())) {
    counters->IncCounter("ERROR-invalid-platform-id:", ShortHostname());
    return absl::InternalError("invalid-platform-id");
  }
  // Snapshot has passed all tests and transformations.
  remade_snapshot_or->NormalizeAll();
  counters->IncCounter("INFO-ALL-OK:", num_end_states);
  return remade_snapshot_or;
}

}  // namespace fix_tool_internal
}  // namespace silifuzz
