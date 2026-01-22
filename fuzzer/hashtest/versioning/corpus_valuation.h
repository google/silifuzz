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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_VERSIONING_CORPUS_VALUATION_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_VERSIONING_CORPUS_VALUATION_H_

#include "./fuzzer/hashtest/runnable_corpus.h"
#include "./fuzzer/hashtest/versioning/corpus_values.pb.h"

namespace silifuzz {

// Get the values for a corpus's tests and inputs for use in equality checking.
proto::CorpusValues GetCorpusValues(const RunnableCorpus& corpus);

}  //  namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_VERSIONING_CORPUS_VALUATION_H_
