// Copyright 2026 The Silifuzz Authors.
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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_RUN_CONFIG_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_RUN_CONFIG_H_

#include <cstddef>
#include <cstdint>

// TODO: b/473040142 - A type named RunConfig using code from testgeneration/
// feels like a mixing between test generation and execution.  Consider fully
// replacing these usages with SynthesisConfig or some other type.
#include "./fuzzer/hashtest/testgeneration/mxcsr.h"

namespace silifuzz {
// The configuration for running a single test.
struct TestConfig {
  size_t vector_width = 0;
  size_t num_iterations = 0;
};

// The configuration for running multiple tests.
struct RunConfig {
  // How should the test be run?
  TestConfig test;

  // How many tests should you alternate between?
  size_t batch_size = 0;

  // How many times should you run each test + input?
  size_t num_repeat = 0;

  // Currently we set the MXCSR once per corpus.
  // It would be possible to set it per test, but this would potentially consume
  // more memory and CPU cycles.
  // TODO(ncbray): is modulating the MXCSR per test worth it?
  uint32_t mxcsr = kMXCSRMaskAll;
};
}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_RUN_CONFIG_H_
