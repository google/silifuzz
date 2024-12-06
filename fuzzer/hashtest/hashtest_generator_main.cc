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

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <random>
#include <string>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "./common/snapshot.h"
#include "./common/snapshot_file_util.h"
#include "./common/snapshot_printer.h"
#include "./fuzzer/hashtest/instruction_pool.h"
#include "./fuzzer/hashtest/synthesize_base.h"
#include "./fuzzer/hashtest/synthesize_snapshot.h"
#include "./instruction/xed_util.h"
#include "./util/checks.h"
#include "./util/enum_flag_types.h"
#include "./util/itoa.h"
#include "./util/line_printer.h"
#include "./util/platform.h"

extern "C" {
#include "third_party/libxed/xed-interface.h"
}

ABSL_FLAG(silifuzz::PlatformId, platform, silifuzz::PlatformId::kUndefined,
          "Platform to target.");

ABSL_FLAG(bool, make, false, "Should the Snapshot be made on this machine?");
ABSL_FLAG(bool, verbose, false, "Print additional debugging information.");
ABSL_FLAG(size_t, n, 1, "Number of tests to generate.");
ABSL_FLAG(std::string, outdir, "", "Output directory to write tests to.");
ABSL_FLAG(std::optional<uint64_t>, seed, std::nullopt,
          "Fixed seed to use for random number generation.");

namespace silifuzz {

absl::Status SynthesizeSnapshots(Rng& rng, xed_chip_enum_t chip,
                                 const InstructionPool& ipool) {
  // If we aren't writing the snapshots to disk, we print them out so they can
  // be inspected. The FP registers matter, so make sure they are printed out.
  LinePrinter line_printer(LinePrinter::StdOutPrinter);
  SnapshotPrinter::Options options = SnapshotPrinter::DefaultOptions();
  options.fp_regs_mode = SnapshotPrinter::kAllFPRegs;
  SnapshotPrinter printer(&line_printer, options);

  // How many snapshots to generate.
  size_t n = absl::GetFlag(FLAGS_n);

  // It can be useful to make the snapshots as they are generated.
  // 1) it verifies that the snapshots are valid.
  // 2) it creates an end state that can be inspected.
  // But this may not always be possible, for example if you are generating for
  // a mircoarch that supports instructions the host does not.
  // Making also significantly slows down the test generation process.
  bool make = absl::GetFlag(FLAGS_make);

  // Where the snapshots should be written.
  std::string outdir = absl::GetFlag(FLAGS_outdir);

  for (size_t i = 0; i < n; ++i) {
    ASSIGN_OR_RETURN_IF_NOT_OK(Snapshot snapshot,
                               SynthesizeTestSnapshot(rng, chip, ipool, make));
    if (!outdir.empty()) {
      std::string outfile = absl::StrCat(outdir, "/", snapshot.id(), ".pb");
      line_printer.Line(absl::StrCat("Writing ", outfile));
      RETURN_IF_NOT_OK(WriteSnapshotToFile(snapshot, outfile));
    } else {
      printer.Print(snapshot);
    }
  }
  return absl::OkStatus();
}

int ToolMain(std::vector<char*> positional_args) {
  InitXedIfNeeded();

  // Determine which platform to target.
  PlatformId platform = absl::GetFlag(FLAGS_platform);
  xed_chip_enum_t chip = PlatformIdToChip(platform);
  QCHECK_NE(chip, XED_CHIP_INVALID)
      << "Unsupported platform: " << EnumStr(platform);

  // Initialize the RNG.
  std::optional<uint64_t> maybe_seed = absl::GetFlag(FLAGS_seed);
  std::random_device hardware_rng{};
  uint64_t seed = maybe_seed.value_or(
      std::uniform_int_distribution<uint64_t>()(hardware_rng));
  Rng rng(seed);

  bool verbose = absl::GetFlag(FLAGS_verbose);

  InstructionPool ipool{};
  GenerateInstructionPool(rng, chip, ipool, verbose);
  CHECK_STATUS(SynthesizeSnapshots(rng, chip, ipool));

  return 0;
}

}  // namespace silifuzz

int main(int argc, char* argv[]) {
  std::vector<char*> positional_args = absl::ParseCommandLine(argc, argv);
  return silifuzz::ToolMain(positional_args);
}
