// Copyright 2023 The SiliFuzz Authors.
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

#include <string>

#include "absl/functional/bind_front.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "./common/snapshot.h"
#include "./player/trace_options.h"
#include "./runner/disassembling_snap_tracer.h"
#include "./runner/driver/runner_driver.h"
#include "./runner/runner_provider.h"
#include "./snap/gen/snap_generator.h"
#include "./util/checks.h"
#include "./util/line_printer.h"
#include "./util/platform.h"

namespace silifuzz {

absl::Status Trace(const Snapshot& snapshot, PlatformId platform_id,
                   LinePrinter* line_printer) {
  SnapifyOptions opts =
      SnapifyOptions::V2InputRunOpts(snapshot.architecture_id());
  opts.platform_id = platform_id;

  ASSIGN_OR_RETURN_IF_NOT_OK(Snapshot snapified, Snapify(snapshot, opts));
  ASSIGN_OR_RETURN_IF_NOT_OK(
      RunnerDriver runner,
      RunnerDriverFromSnapshot(snapified, RunnerLocation()));

  TraceOptions trace_options = TraceOptions::Default();
  // Don't be opinionated about non-deterministic code like we are in SnapMaker.
  // If there's an existing (possibly, legacy) snapshot with non-deterministic
  // instructions just trace it.
  trace_options.filter_non_deterministic_insn = false;
  DisassemblingSnapTracer tracer(snapshot, trace_options);
  auto trace_fn = absl::bind_front(&DisassemblingSnapTracer::Step, &tracer);
  absl::StatusOr<RunnerDriver::RunResult> trace_result =
      runner.TraceOne(snapshot.id(), trace_fn);
  DisassemblingSnapTracer::TraceResult trace_data = tracer.trace_result();
  for (const std::string& s : trace_data.disassembly) {
    line_printer->Line(s);
  }

  RETURN_IF_NOT_OK(trace_result.status());
  if (!trace_result->success()) {
    return absl::InternalError(
        absl::StrCat("Tracing failed: ", trace_data.early_termination_reason));
  }
  return absl::OkStatus();
}

}  // namespace silifuzz
