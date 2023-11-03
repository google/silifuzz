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
#include <string>
#include <utility>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./common/snapshot.h"
#include "./common/snapshot_test_enum.h"
#include "./common/snapshot_test_util.h"
#include "./snap/gen/relocatable_snap_generator.h"
#include "./snap/gen/snap_generator.h"
#include "./snap/testing/snap_test_snapshots.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/file_util.h"
#include "./util/misc_util.h"
#include "./util/mmapped_memory_ptr.h"

ABSL_FLAG(std::string, snapshot_id, "",
          "Generate a corpus with a single, named snapshot.");

ABSL_FLAG(std::string, arch, "",
          "Architecture to target. One of x86_64, aarch64.");

namespace silifuzz {
namespace {

bool ShouldIncludeSnapshot(const Snapshot& snapshot) {
  std::string snapshot_id = absl::GetFlag(FLAGS_snapshot_id);
  if (!snapshot_id.empty()) {
    return snapshot.id() == snapshot_id;
  } else {
    return true;
  }
}

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
    if (!ShouldIncludeSnapshot(snapshot)) {
      continue;
    }
    // Note: it isn't guaranteed that all the test snaps will be snap
    // compatible. If this becomes an issue, we can add a query function and
    // filter them out here.
    ASSIGN_OR_RETURN_IF_NOT_OK(Snapshot snapified, Snapify(snapshot, opts));
    snapified_corpus.push_back(std::move(snapified));
  }

  // Check if we filtered out everything due to a bad snapshot_id.
  CHECK_GE(snapified_corpus.size(), 1);

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
absl::Status MainImpl() {
  return GenerateRelocatableRunnerCorpus<Arch>();
}

absl::Status Main(const std::string& arch) {
  if (arch == "x86_64") {
    return MainImpl<X86_64>();
  } else if (arch == "aarch64") {
    return MainImpl<AArch64>();
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
  absl::Status result = silifuzz::Main(arch);
  if (!result.ok()) {
    LOG_ERROR(result.message());
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
