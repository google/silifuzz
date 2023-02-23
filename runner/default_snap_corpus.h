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
// On successful load, `*corpus_fd` will be set to the descriptor of the file
// object that backs the corpus, if such an object exists. The caller takes
// ownership of this descriptor and is responsible for closing it. If the
// backing file object does not exist, `*corpus_fd` will be -1. If `corpus_fd`
// is NULL, no descriptor is returned.
const SnapCorpus* LoadCorpus(const char* filename, int* corpus_fd);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_RUNNER_DEFAULT_SNAP_CORPUS_H_
