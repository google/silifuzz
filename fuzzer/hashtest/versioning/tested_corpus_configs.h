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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_VERSIONING_TESTED_CORPUS_CONFIGS_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_VERSIONING_TESTED_CORPUS_CONFIGS_H_

#include "absl/strings/string_view.h"
#include "./fuzzer/hashtest/testgeneration/corpus_generator.h"

namespace silifuzz {

// A basic configuration.
constexpr GenerationConfig kBasicConfig = {
    .num_inputs = 10,
    .num_tests = 100,
    .flag_capture_rate = 0.5f,
    .mask_trap_flag = true,
    .min_duplication_rate = 0.0f,
    .max_duplication_rate = 0.5f,
    .branch_test_bits = 3,
    .chip = XED_CHIP_SKYLAKE,
    .seed = 0x1,
};

constexpr absl::string_view kBasicConfigFileName = "basic_config_golden.pb";

// A configuration with 10x the number of inputs.
constexpr GenerationConfig kManyInputsConfig = {
    .num_inputs = 100,
    .num_tests = 100,
    .flag_capture_rate = 0.5f,
    .mask_trap_flag = true,
    .min_duplication_rate = 0.0f,
    .max_duplication_rate = 0.5f,
    .branch_test_bits = 3,
    .chip = XED_CHIP_SKYLAKE,
    .seed = 0x2,
};

constexpr absl::string_view kManyInputsConfigFileName =
    "many_inputs_config_golden.pb";

// A configuration with 10x the number of tests.
constexpr GenerationConfig kManyTestsConfig = {
    .num_inputs = 10,
    .num_tests = 1000,
    .flag_capture_rate = 0.5f,
    .mask_trap_flag = true,
    .min_duplication_rate = 0.0f,
    .max_duplication_rate = 0.5f,
    .branch_test_bits = 3,
    .chip = XED_CHIP_SKYLAKE,
    .seed = 0x3,
};

constexpr absl::string_view kManyTestsConfigFileName =
    "many_tests_config_golden.pb";

// A configuration with a lot of duplication and flag captures
constexpr GenerationConfig kHighlyDuplicatedConfig = {
    .num_inputs = 10,
    .num_tests = 100,
    .flag_capture_rate = 0.8f,
    .mask_trap_flag = true,
    .min_duplication_rate = 0.25f,
    .max_duplication_rate = 1.5f,
    .branch_test_bits = 3,
    .chip = XED_CHIP_SAPPHIRE_RAPIDS,
    .seed = 0x4,
};

constexpr absl::string_view kHighlyDuplicatedConfigFileName =
    "highly_duplicated_config_golden.pb";

// A configuration with no flag captures.
constexpr GenerationConfig kCapturelessConfig = {
    .num_inputs = 10,
    .num_tests = 100,
    .flag_capture_rate = 0,
    .mask_trap_flag = true,
    .min_duplication_rate = 0.0f,
    .max_duplication_rate = 0.5f,
    .branch_test_bits = 3,
    .chip = XED_CHIP_SKYLAKE,
    .seed = 0x5,
};

constexpr absl::string_view kCapturelessConfigFileName =
    "no_capture_config_golden.pb";

// A configuration with no duplication
constexpr GenerationConfig kNoDuplicationConfig = {
    .num_inputs = 10,
    .num_tests = 100,
    .flag_capture_rate = 0.5f,
    .mask_trap_flag = true,
    .min_duplication_rate = 0.0f,
    .max_duplication_rate = 0.0f,
    .branch_test_bits = 3,
    .chip = XED_CHIP_SKYLAKE,
    .seed = 0x6,
};

constexpr absl::string_view kNoDuplicationConfigFileName =
    "no_duplication_config_golden.pb";

// A configuration with no branching
constexpr GenerationConfig kFullyPredictableBranchConfig = {
    .num_inputs = 10,
    .num_tests = 100,
    .flag_capture_rate = 0.5f,
    .mask_trap_flag = true,
    .min_duplication_rate = 0.0f,
    .max_duplication_rate = 0.5f,
    .branch_test_bits = 0,
    .chip = XED_CHIP_SKYLAKE,
    .seed = 0x7,
};

constexpr absl::string_view kFullyPredictableBranchConfigFileName =
    "fully_predicatable_branch_config_golden.pb";

// A configuration targeting an older chip
constexpr GenerationConfig kHaswellConfig = {
    .num_inputs = 10,
    .num_tests = 100,
    .flag_capture_rate = 0.5f,
    .mask_trap_flag = true,
    .min_duplication_rate = 0.0f,
    .max_duplication_rate = 0.5f,
    .branch_test_bits = 3,
    .chip = XED_CHIP_HASWELL,
    .seed = 0x8,
};

constexpr absl::string_view kHaswellConfigFileName = "haswell_config_golden.pb";

// A configuration targeting a newer chip
constexpr GenerationConfig kSapphireRapidsConfig = {
    .num_inputs = 10,
    .num_tests = 100,
    .flag_capture_rate = 0.5f,
    .mask_trap_flag = true,
    .min_duplication_rate = 0.0f,
    .max_duplication_rate = 0.5f,
    .branch_test_bits = 3,
    .chip = XED_CHIP_SAPPHIRE_RAPIDS,
    .seed = 0x9,
};

constexpr absl::string_view kSapphireRapidsConfigFileName =
    "sapphire_rapids_config_golden.pb";

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_VERSIONING_TESTED_CORPUS_CONFIGS_H_
