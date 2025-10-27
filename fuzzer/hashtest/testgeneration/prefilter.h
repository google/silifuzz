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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TESTGENERATION_PREFILTER_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TESTGENERATION_PREFILTER_H_

extern "C" {
#include "third_party/libxed/xed-interface.h"
}

namespace silifuzz {

// Returns true if this instruction may be something we want to test. This
// instruction may later be filtered out for other reasons.
// Returns false if the instruction is obviously something we do not want to
// test.
bool PrefilterInstruction(const xed_inst_t* instruction);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TESTGENERATION_PREFILTER_H_
