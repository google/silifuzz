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
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./common/snapshot.h"
#include "./common/snapshot_util.h"
#include "./player/trace_options.h"
#include "./runner/make_snapshot.h"
#include "./runner/runner_provider.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/hostname.h"
#include "./util/itoa.h"
#include "./util/page_util.h"
#include "./util/platform.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {
namespace fix_tool_internal {
namespace {

// Runs `snapshot` through the maker to construct end state and verifies
// the remade snapshot to filter out any problematic snapshot.
// Returns the remade snapshot or an error status.
absl::StatusOr<Snapshot> RemakeAndVerify(const Snapshot& snapshot,
                                         const FixupSnapshotOptions& options) {
  MakingConfig config = MakingConfig::Default(RunnerLocation());
  config.trace.x86_filter_split_lock = options.x86_filter_split_lock;
  config.trace.x86_filter_vsyscall_region_access =
      options.x86_filter_vsyscall_region_access;
  config.trace.filter_memory_access = options.filter_memory_access;
  config.enforce_fuzzing_config = options.enforce_fuzzing_config;
  config.trace.x86_filter_non_canonical_evex_sp =
      options.x86_filter_non_canonical_evex_sp;
  config.cpu_time_budget = options.cpu_time_budget;

  return MakeSnapshot(snapshot, config);
}

}  // namespace

bool NormalizeSnapshot(Snapshot& snapshot, FixToolCounters* counters) {
  // If there's a single end state keep it
  bool has_one_endstate = snapshot.expected_end_states().size() == 1 &&
                          snapshot.IsCompleteSomeState().ok();
  if (!has_one_endstate) {
    // Otherwise, replace all expected end states with a single undefined.
    const uint64_t kPageSizeBytes = snapshot.page_size();
    Snapshot::Address orig_endpoint_address =
        snapshot.ExtractRip(snapshot.registers());
    // "Imagine" an endpoint at the end of the code page. 15 bytes is the
    // padding for the exit V2 sequence.
    orig_endpoint_address =
        RoundDownToPageAlignment(orig_endpoint_address, kPageSizeBytes) +
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

bool EditInitialRegisters(GRegSet<X86_64>& gregs, FPRegSet<X86_64>& fpregs) {
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

  return changed;
}

bool EditInitialRegisters(GRegSet<AArch64>& gregs, FPRegSet<AArch64>& fpregs) {
  // No editing needed, yet.
  return false;
}

template <typename Arch>
bool RewriteInitialStateImpl(Snapshot& snapshot, FixToolCounters* counters) {
  GRegSet<Arch> gregs;
  FPRegSet<Arch> fpregs;
  CHECK_STATUS(ConvertRegsFromSnapshot(snapshot.registers(), &gregs, &fpregs));

  bool changed = EditInitialRegisters(gregs, fpregs);

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

bool RewriteInitialState(Snapshot& snapshot, FixToolCounters* counters) {
  return ARCH_DISPATCH(RewriteInitialStateImpl, snapshot.architecture_id(),
                       snapshot, counters);
}

std::string SnapshotOrigin(const Snapshot& input) {
  if (input.metadata().origin() == Snapshot::Metadata::Origin::kUseString) {
    return std::string(input.metadata().origin_string());
  }
  return std::string(EnumStr(input.metadata().origin()));
}

absl::StatusOr<Snapshot> FixupSnapshot(const Snapshot& input,
                                       const FixupSnapshotOptions& options,
                                       PlatformFixToolCounters* counters) {
  const std::string origin = SnapshotOrigin(input);

  // Count the number of inputs so we can easily normalize the counters that
  // come after this - both per-origin and aggregated counters.
  counters->IncOriginCounter(origin, "INFO-INPUT");

  absl::StatusOr<Snapshot> remade_snapshot_or = RemakeAndVerify(input, options);
  if (!remade_snapshot_or.ok()) {
    counters->IncOriginCounter(
        origin, "ERROR-Make:", remade_snapshot_or.status().message());
    return remade_snapshot_or.status();
  }

  int num_end_states = remade_snapshot_or->expected_end_states().size();
  if (num_end_states > 1) {
    counters->IncOriginCounter(origin,
                               "ERROR-multi-state-test:", num_end_states);
    return absl::InternalError("multi-state-test");
  }

  if (num_end_states == 0) {
    counters->IncOriginCounter(origin,
                               "ERROR-zero-end-states-test:", num_end_states);
    return absl::InternalError("zero-end-states-test");
  }
  // Sanity check the only expected end state -- it must have the current
  // platform.
  if (!remade_snapshot_or->expected_end_states()[0].has_platform(
          CurrentPlatformId())) {
    counters->IncOriginCounter(origin,
                               "ERROR-invalid-platform-id:", ShortHostname());
    return absl::InternalError("invalid-platform-id");
  }
  // Snapshot has passed all tests and transformations.
  remade_snapshot_or->NormalizeAll();
  counters->IncOriginCounter(origin, "INFO-ALL-OK:", num_end_states);
  return remade_snapshot_or;
}

}  // namespace fix_tool_internal
}  // namespace silifuzz
