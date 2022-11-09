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

#ifndef THIRD_PARTY_SILIFUZZ_RUNNER_DEFAULT_SNAP_CORPUS_H_
#define THIRD_PARTY_SILIFUZZ_RUNNER_DEFAULT_SNAP_CORPUS_H_
#include "./snap/snap.h"

namespace silifuzz {

// Returns a pointer to the Snap array.
// The `filename` is the first non-flag command line argument passed to the
// binary or nullptr if there wasn't any.
const SnapCorpus* LoadCorpus(const char* filename);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_RUNNER_DEFAULT_SNAP_CORPUS_H_
