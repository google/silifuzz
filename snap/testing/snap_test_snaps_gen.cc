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

#include <unistd.h>

#include <cstdlib>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./common/snapshot.h"
#include "./common/snapshot_test_enum.h"
#include "./common/snapshot_test_util.h"
#include "./snap/gen/relocatable_snap_generator.h"
#include "./snap/gen/snap_generator.h"
#include "./snap/testing/snap_test_snapshots.h"
#include "./snap/testing/snap_test_types.h"
#include "./util/checks.h"
#include "./util/file_util.h"
#include "./util/misc_util.h"
#include "./util/mmapped_memory_ptr.h"

ABSL_FLAG(std::string, arch, "",
          "Architecture to target. One of x86_64, aarch64.");

ABSL_FLAG(
    std::string, output_mode, "c++source",
    "Kind of output to generate. One of c++source, relocatable_runner_corpus");

namespace silifuzz {
namespace {

template <typename Arch>
absl::Status GenerateRelocatableRunnerCorpus() {
  SnapifyOptions opts = SnapifyOptions::V2InputRunOpts(Arch::architecture_id);
  opts.compress_repeating_bytes = true;

  // Build the test Snapshot corpus.
  std::vector<std::string> runner_test_snap_names;
  std::vector<Snapshot> snapified_corpus;
  for (int index = 0; index < ToInt(TestSnapshot::kNumTestSnapshot); ++index) {
    TestSnapshot type = static_cast<TestSnapshot>(index);
    if (!TestSnapshotExists<Arch>(type)) {
      continue;
    }
    Snapshot snapshot = MakeSnapRunnerTestSnapshot<Arch>(type);
    // Note: it isn't guarenteed that all the test snaps will be snap
    // compatible. If this becomes an issue, we can add a query function and
    // filter them out here.
    ASSIGN_OR_RETURN_IF_NOT_OK(Snapshot snapified, Snapify(snapshot, opts));
    snapified_corpus.push_back(std::move(snapified));
  }

  // Generate the SnapCorpus data.
  RelocatableSnapGeneratorOptions options;
  options.compress_repeating_bytes = opts.compress_repeating_bytes;
  MmappedMemoryPtr<char> buffer = GenerateRelocatableSnaps(
      Arch::architecture_id, snapified_corpus, options);

  // Output.
  absl::string_view buf(buffer.get(), MmappedMemorySize(buffer));
  if (!WriteToFileDescriptor(STDOUT_FILENO, buf)) {
    return absl::InternalError("WriteToFileDescriptor failed");
  }

  return absl::OkStatus();
}

template <typename Arch>
absl::Status GenerateSource() {
  SnapifyOptions snapify_opts =
      SnapifyOptions::V2InputRunOpts(Arch::architecture_id);

  SnapGenerator<Arch> generator(std::cout);
  generator.IncludeLocalHeader("./snap/testing/snap_test_snaps.h");
  generator.FileStart();

  // Generate generator test snaps.
  std::vector<std::string> generator_test_snap_names;
  const int first_generator_test_type =
      ToInt(SnapGeneratorTestType::kFirstSnapGeneratorTest);
  const int last_generator_test_type =
      ToInt(SnapGeneratorTestType::kLastSnapGeneratorTest);
  for (int type = first_generator_test_type; type <= last_generator_test_type;
       ++type) {
    SnapGeneratorTestType snap_generator_test_type =
        static_cast<SnapGeneratorTestType>(type);
    Snapshot snapshot =
        MakeSnapGeneratorTestSnapshot<Arch>(snap_generator_test_type);
    std::string name = absl::StrCat("kGeneratorTestSnap_", type);
    generator_test_snap_names.push_back(name);
    CHECK_STATUS(generator.GenerateSnap(name, snapshot, snapify_opts));
  }

  // We use types as array indices.
  CHECK_EQ(first_generator_test_type, 0);
  CHECK_EQ(last_generator_test_type + 1, generator_test_snap_names.size());

  // Print SnapArray containing pointers to Snaps generated above.
  generator.GenerateSnapArray("kSnapGeneratorTestCorpus",
                              generator_test_snap_names);

  // Generate runner test snaps.
  std::vector<std::string> runner_test_snap_names;
  for (int index = 0; index < ToInt(TestSnapshot::kNumTestSnapshot); ++index) {
    TestSnapshot type = static_cast<TestSnapshot>(index);
    if (!TestSnapshotExists<Arch>(type)) {
      continue;
    }
    Snapshot snapshot = MakeSnapRunnerTestSnapshot<Arch>(type);
    std::string name = absl::StrCat("kRunnerTestSnap_", index);
    runner_test_snap_names.push_back(name);
    CHECK_STATUS(generator.GenerateSnap(name, snapshot, snapify_opts));
  }

  // Print SnapArray containing pointers to Snaps generated above.
  generator.GenerateSnapArray("kSnapRunnerTestCorpus", runner_test_snap_names);

  // Also use the same runner test snaps to produce the default corpus.
  generator.GenerateSnapArray("kDefaultSnapCorpus", runner_test_snap_names);

  generator.FileEnd();

  return absl::OkStatus();
}

template <typename Arch>
absl::Status MainImpl(const std::string& mode) {
  if (mode == "c++source") {
    return GenerateSource<Arch>();
  } else if (mode == "relocatable_runner_corpus") {
    return GenerateRelocatableRunnerCorpus<Arch>();
  } else {
    return absl::InvalidArgumentError("Unsupported mode");
  }
}

absl::Status Main(const std::string& arch, const std::string& mode) {
  if (arch == "x86_64") {
    return MainImpl<X86_64>(mode);
  } else if (arch == "aarch64") {
    return MainImpl<AArch64>(mode);
  } else if (arch.empty()) {
    return absl::InvalidArgumentError("--arch is required");
  } else {
    return absl::InvalidArgumentError("Unsupported arch");
  }
}

}  // namespace
}  // namespace silifuzz

int main(int argc, char* argv[]) {
  absl::ParseCommandLine(argc, argv);
  std::string arch = absl::GetFlag(FLAGS_arch);
  std::string mode = absl::GetFlag(FLAGS_output_mode);
  absl::Status result = silifuzz::Main(arch, mode);
  if (!result.ok()) {
    LOG_ERROR(result.message());
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
