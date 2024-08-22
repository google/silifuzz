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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_HASHTEST_WIDGITS_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_HASHTEST_WIDGITS_H_

#include <cstddef>

namespace silifuzz {

struct EntropyBuffer;

// Run a test on a CPU that supports AVX-512.
// `test` is a pointer to executable memory containing a hash test. This test
// will be entered with a "call" and exit back to the caller. The test will
// expect the registers state to be initialized in a specific way (not the
// standard C calling convention) and that setup is taken care of by this
// wrapper function.
// `input` is the initial register state of the test.
// `num_iterations` is the number of times the main loop of the test should
// iterate.
// `output` is the register state after executing the test.
extern "C" void RunHashTest512(void* test, size_t num_iterations,
                               const EntropyBuffer* input,
                               EntropyBuffer* output);

// Run a test on a CPU that supports AVX2.
extern "C" void RunHashTest256(void* test, size_t num_iterations,
                               const EntropyBuffer* input,
                               EntropyBuffer* output);

// A function that does nothing but return.
// Registers should be undisturbed.
// Useful for testing the other functions in this header.
extern "C" void NopTest(void);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_HASHTEST_WIDGITS_H_
