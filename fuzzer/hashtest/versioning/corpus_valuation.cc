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

#include "./fuzzer/hashtest/versioning/corpus_valuation.h"

#include "./fuzzer/hashtest/runnable_corpus.h"
#include "./fuzzer/hashtest/versioning/corpus_values.pb.h"
#include "./fuzzer/hashtest/versioning/version.h"

namespace silifuzz {

proto::CorpusValues GetCorpusValues(const RunnableCorpus& corpus) {
  proto::CorpusValues values;
  values.set_version(GetVersionString());

  for (int i = 0; i < corpus.inputs.size(); ++i) {
    auto* input_value = values.add_input_value();
    input_value->set_seed(corpus.inputs[i].seed);
    input_value->set_hash(corpus.inputs[i].BufferHash());
  }
  for (int i = 0; i < corpus.tests.size(); ++i) {
    auto* test_value = values.add_test_value();
    test_value->set_seed(corpus.tests[i].seed);
    test_value->set_hash(corpus.tests[i].TestContentHash(corpus.mapping));
  }

  return values;
}

}  //  namespace silifuzz
