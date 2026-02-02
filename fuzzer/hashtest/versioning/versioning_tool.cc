// Copyright 2026 The SiliFuzz Authors.
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

// Tool for validating that the current version number is correct based on
// the files stored in goldens/.  Also has the ability to update the files
// if the version number needs to change.
#include <cstdlib>
#include <functional>
#include <iostream>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./fuzzer/hashtest/parallel_worker_pool.h"
#include "./fuzzer/hashtest/runnable_corpus.h"
#include "./fuzzer/hashtest/testgeneration/candidate.h"
#include "./fuzzer/hashtest/testgeneration/corpus_generator.h"
#include "./fuzzer/hashtest/versioning/corpus_valuation.h"
#include "./fuzzer/hashtest/versioning/corpus_values.pb.h"
#include "./fuzzer/hashtest/versioning/tested_corpus_configs.h"
#include "./instruction/xed_util.h"
#include "./util/proto_util.h"
#include "./util/tool_util.h"

ABSL_FLAG(std::optional<std::string>, golden_dir, std::nullopt,
          "Directory to which you either want to write the golden files (for "
          "update command) or read the golden files (for verify command). Do "
          "not include the final /");

namespace silifuzz {
namespace {

// The list of possible commands for the tool.
constexpr absl::string_view kUpdateCommand = "update";
constexpr absl::string_view kVerifyCommand = "verify";

// How many threads should be used in the worker pool.
constexpr int kNumThreads = 10;

constexpr std::pair<const GenerationConfig, const absl::string_view>
    kConfigsArr[] = {
        std::pair(kBasicConfig, kBasicConfigFileName),
        std::pair(kManyInputsConfig, kManyInputsConfigFileName),
        std::pair(kManyTestsConfig, kManyTestsConfigFileName),
        std::pair(kHighlyDuplicatedConfig, kHighlyDuplicatedConfigFileName),
        std::pair(kCapturelessConfig, kCapturelessConfigFileName),
        std::pair(kNoDuplicationConfig, kNoDuplicationConfigFileName),
        std::pair(kFullyPredictableBranchConfig,
                  kFullyPredictableBranchConfigFileName),
        std::pair(kHaswellConfig, kHaswellConfigFileName),
        std::pair(kSapphireRapidsConfig, kSapphireRapidsConfigFileName)};

absl::string_view TrimPatchVersion(absl::string_view version) {
  size_t trim_pos = version.rfind('.');
  version.remove_suffix(version.size() - trim_pos);
  return version;
}

bool MajorMinorVersionEquals(absl::string_view version_a,
                             absl::string_view version_b) {
  return TrimPatchVersion(version_a) == TrimPatchVersion(version_b);
}

}  // namespace

int CompareCorpusValues(const proto::CorpusValues& generated,
                        const proto::CorpusValues& golden) {
  if (!MajorMinorVersionEquals(generated.version(), golden.version())) {
    std::cerr << "Incompatible versions, please update golden values"
              << std::endl;
    return EXIT_FAILURE;
  }

  if (generated.input_value_size() != golden.input_value_size()) {
    std::cerr << "Different number of inputs" << std::endl;
    return EXIT_FAILURE;
  }
  if (generated.test_value_size() != golden.test_value_size()) {
    std::cerr << "Different number of tests" << std::endl;
    return EXIT_FAILURE;
  }

  int different_input_seeds = 0;
  int different_input_hashes = 0;
  for (int i = 0; i < generated.input_value_size(); ++i) {
    if (generated.input_value(i).seed() != golden.input_value(i).seed()) {
      ++different_input_seeds;
    }
    if (generated.input_value(i).hash() != golden.input_value(i).hash()) {
      ++different_input_hashes;
    }
  }

  int different_test_seeds = 0;
  int different_test_hashes = 0;
  for (int i = 0; i < generated.test_value_size(); ++i) {
    if (generated.test_value(i).seed() != golden.test_value(i).seed()) {
      ++different_test_seeds;
    }
    if (generated.test_value(i).hash() != golden.test_value(i).hash()) {
      ++different_test_hashes;
    }
  }

  if (different_input_seeds != 0 || different_input_hashes != 0 ||
      different_test_seeds != 0 || different_test_hashes != 0) {
    std::cerr << "Detected differences between Golden and Generated: "
              << std::endl;
    std::cerr << "\t" << different_input_seeds << " different input seeds"
              << std::endl;
    std::cerr << "\t" << different_input_hashes << " different input hashes"
              << std::endl;
    std::cerr << "\t" << different_test_seeds << " different test seeds"
              << std::endl;
    std::cerr << "\t" << different_test_hashes << " different test hashes"
              << std::endl;
    return EXIT_FAILURE;
  }
  std::cerr << "Golden and Generated are Equal" << std::endl;
  return EXIT_SUCCESS;
}

proto::CorpusValues GenerateValuesForConfig(
    const GenerationConfig& config,
    std::function<bool(const InstructionCandidate&)> filter) {
  InitXedIfNeeded();
  ParallelWorkerPool worker_pool(kNumThreads);

  CorpusGenerator corpus_generator;
  RunnableCorpus corpus =
      corpus_generator.GenerateCorpusForConfig(config, filter, worker_pool);

  return GetCorpusValues(corpus);
}

int UpdateGoldenFiles(absl::string_view golden_dir) {
  for (const auto& [config, filename] : kConfigsArr) {
    std::cerr << "Generating corpus for " << filename << std::endl;
    proto::CorpusValues values = GenerateValuesForConfig(
        config, [](const InstructionCandidate&) { return true; });

    std::string file_path = absl::StrCat(golden_dir, "/", filename);
    std::cerr << "Writing golden to " << file_path << std::endl;

    if (auto status = WriteToFile(values, file_path); !status.ok()) {
      std::cerr << "Failed to write basic config to file:" << status.ToString()
                << std::endl;
      return EXIT_FAILURE;
    }
  }
  return EXIT_SUCCESS;
}

int VerifyGoldenFiles(absl::string_view golden_dir) {
  bool failed = false;
  for (const auto& [config, filename] : kConfigsArr) {
    proto::CorpusValues values = GenerateValuesForConfig(
        config, [](const InstructionCandidate&) { return true; });

    std::string file_path = absl::StrCat(golden_dir, "/", filename);
    proto::CorpusValues golden_values;
    if (auto status = ReadFromFile(file_path, &golden_values); !status.ok()) {
      std::cerr << "Failed to read golden file (" << filename
                << "): " << status.ToString() << std::endl;
      failed = true;
      continue;
    }
    std::cout << "Checking: " << filename << std::endl;
    if (CompareCorpusValues(values, golden_values) == EXIT_FAILURE) {
      failed = true;
    }
  }
  if (failed) {
    return EXIT_FAILURE;
  } else {
    return EXIT_SUCCESS;
  }
}

int VersioningMain(std::vector<char*>& args) {
  ConsumeArg(args);  // skip binary's name

  if (args.empty()) {
    std::cerr << "Expected one of {" << kUpdateCommand << ", " << kVerifyCommand
              << "}, but got none of them" << std::endl;
    return EXIT_FAILURE;
  }

  std::optional<std::string> golden_dir_flag = absl::GetFlag(FLAGS_golden_dir);
  if (!golden_dir_flag) {
    std::cerr << "Need a value for --golden_dir" << std::endl;
    return EXIT_FAILURE;
  }

  std::string command = ConsumeArg(args);
  if (command == kUpdateCommand) {
    return UpdateGoldenFiles(*golden_dir_flag);
  } else if (command == kVerifyCommand) {
    return VerifyGoldenFiles(*golden_dir_flag);
  }
  std::cerr << "Not a recognized command: " << command << std::endl;
  return EXIT_FAILURE;
}
}  // namespace silifuzz

int main(int argc, char* argv[]) {
  std::vector<char*> positional_args = absl::ParseCommandLine(argc, argv);
  return silifuzz::VersioningMain(positional_args);
}
