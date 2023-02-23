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

#include "./runner/default_snap_corpus.h"
#include "./snap/snap.h"

namespace silifuzz {

// This is the corpus we use in baked-in mode.
// The corpus can come from different sources. In the typical usage, a tool
// generates a Snap::Corpus of the same name. The array is then linked into the
// snap runner binary.
// See snap_examples.cc for an example usage.
extern const SnapCorpus kDefaultSnapCorpus;

const SnapCorpus* LoadCorpus(const char* filename, int* corpus_fd) {
  if (corpus_fd != nullptr) {
    *corpus_fd = -1;
  }
  return &kDefaultSnapCorpus;
}

}  // namespace silifuzz
