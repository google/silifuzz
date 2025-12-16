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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TESTGENERATION_SYNTHESIZE_SNAPSHOT_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TESTGENERATION_SYNTHESIZE_SNAPSHOT_H_

#include <random>

#include "absl/status/statusor.h"
#include "./common/snapshot.h"
#include "./fuzzer/hashtest/testgeneration/synthesize_test.h"

namespace silifuzz {

absl::StatusOr<Snapshot> SynthesizeTestSnapshot(std::mt19937_64& rng,
                                                xed_chip_enum_t chip,
                                                const SynthesisConfig& config,
                                                bool make);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTES_TESTGENERATIONT_SYNTHESIZE_SNAPSHOT_H_
