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

#ifndef THIRD_PARTY_SILIFUZZ_RUNNER_RUNNER_PROVIDER_H_
#define THIRD_PARTY_SILIFUZZ_RUNNER_RUNNER_PROVIDER_H_

#include <string>

// This library defines a bunch of methods to obtain path(s) to the runner
// binary.

namespace silifuzz {

// Returns the one runner binary location.
std::string RunnerLocation();

// Returns location of the runner_test_helper_nolibc binary.
// NOTE: The caller must ensure that the runner/runner_test_helper_nolibc is a
// data dependency of the corresponding build target.
std::string RunnerTestHelperLocation();

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_RUNNER_RUNNER_PROVIDER_H_
