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
#include "./snap/gen/relocatable_snap_generator.h"
#include "./snap/gen/snap_generator.h"
#include "./snap/testing/snap_test_snapshots.h"
#include "./snap/testing/snap_test_types.h"
#include "./util/checks.h"
#include "./util/file_util.h"
#include "./util/misc_util.h"
#include "./util/mmapped_memory_ptr.h"

ABSL_FLAG(
    std::string, output_mode, "c++source",
    "Kind of output to generate. One of c++source, relocatable_runner_corpus");

namespace silifuzz {
namespace {

absl::Status GenerateRelocatableRunnerCorpus() {
  SnapGenerator::VarNameList runner_test_snap_names;
  const int first_runner_test_type =
      ToInt(SnapRunnerTestType::kFirstSnapRunnerTest);
  const int last_runner_test_type =
      ToInt(SnapRunnerTestType::kLastSnapRunnerTest);
  std::vector<Snapshot> snapified_corpus;
  SnapGenerator::Options opts = SnapGenerator::Options::V2InputRunOpts();
  opts.compress_repeating_bytes = true;
  for (int type = first_runner_test_type; type <= last_runner_test_type;
       ++type) {
    Snapshot snapshot =
        MakeSnapRunnerTestSnapshot(static_cast<SnapRunnerTestType>(type));
    ASSIGN_OR_RETURN_IF_NOT_OK(Snapshot snapified,
                               SnapGenerator::Snapify(snapshot, opts));
    snapified_corpus.push_back(std::move(snapified));
  }
  RelocatableSnapGeneratorOptions options;
  options.compress_repeating_bytes = opts.compress_repeating_bytes;
  MmappedMemoryPtr<char> buffer =
      GenerateRelocatableSnaps(snapified_corpus, options);
  absl::string_view buf(buffer.get(), MmappedMemorySize(buffer));
  if (!WriteToFileDescriptor(STDOUT_FILENO, buf)) {
    return absl::InternalError("WriteToFileDescriptor failed");
  }

  return absl::OkStatus();
}

absl::Status GenerateSource() {
  SnapGenerator generator(std::cout);
  generator.IncludeLocalHeader("./snap/testing/snap_test_snaps.h");
  generator.FileStart();

  // Generate generator test snaps.
  SnapGenerator::VarNameList generator_test_snap_names;
  const int first_generator_test_type =
      ToInt(SnapGeneratorTestType::kFirstSnapGeneratorTest);
  const int last_generator_test_type =
      ToInt(SnapGeneratorTestType::kLastSnapGeneratorTest);
  for (int type = first_generator_test_type; type <= last_generator_test_type;
       ++type) {
    SnapGeneratorTestType snap_generator_test_type =
        static_cast<SnapGeneratorTestType>(type);
    Snapshot snapshot = MakeSnapGeneratorTestSnapshot(snap_generator_test_type);
    std::string name = absl::StrCat("kGeneratorTestSnap_", type);
    generator_test_snap_names.push_back(name);
    CHECK_STATUS(generator.GenerateSnap(name, snapshot));
  }

  // We use types as array indices.
  CHECK_EQ(first_generator_test_type, 0);
  CHECK_EQ(last_generator_test_type + 1, generator_test_snap_names.size());

  // Print SnapArray containing pointers to Snaps generated above.
  generator.GenerateSnapArray("kSnapGeneratorTestCorpus",
                              generator_test_snap_names);

  // Generate runner test snaps.
  SnapGenerator::VarNameList runner_test_snap_names;
  const int first_runner_test_type =
      ToInt(SnapRunnerTestType::kFirstSnapRunnerTest);
  const int last_runner_test_type =
      ToInt(SnapRunnerTestType::kLastSnapRunnerTest);
  for (int type = first_runner_test_type; type <= last_runner_test_type;
       ++type) {
    Snapshot snapshot =
        MakeSnapRunnerTestSnapshot(static_cast<SnapRunnerTestType>(type));
    std::string name = absl::StrCat("kRunnerTestSnap_", type);
    runner_test_snap_names.push_back(name);
    CHECK_STATUS(generator.GenerateSnap(name, snapshot));
  }

  // We use types as array indices.
  CHECK_EQ(first_runner_test_type, 0);
  CHECK_EQ(last_runner_test_type + 1, runner_test_snap_names.size());

  // Print SnapArray containing pointers to Snaps generated above.
  generator.GenerateSnapArray("kSnapRunnerTestCorpus", runner_test_snap_names);

  // Also use the same runner test snaps to produce the default corpus.
  generator.GenerateSnapArray("kDefaultSnapCorpus", runner_test_snap_names);

  generator.FileEnd();

  return absl::OkStatus();
}

}  // namespace
}  // namespace silifuzz

int main(int argc, char* argv[]) {
  absl::ParseCommandLine(argc, argv);
  std::string mode = absl::GetFlag(FLAGS_output_mode);
  absl::Status result = [&mode]() {
    if (mode == "c++source") {
      return silifuzz::GenerateSource();
    } else if (mode == "relocatable_runner_corpus") {
      return silifuzz::GenerateRelocatableRunnerCorpus();
    } else {
      return absl::InvalidArgumentError("Unsupported mode");
    }
  }();
  if (!result.ok()) {
    LOG_ERROR(result.message());
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
