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

#ifndef THIRD_PARTY_SILIFUZZ_SNAP_SNAP_CORPUS_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_SNAP_SNAP_CORPUS_UTIL_H_

#include "./snap/snap.h"
#include "./util/mmapped_memory_ptr.h"

// Library for handling relocatable snap corpus.
// See relocatable_snap_generator.h for details on the file format.
namespace silifuzz {

// Loads relocatable Snap corpus from `filename`. CHECK-fails on any error.
// When `preload` is true, preloads the file into memory using MAP_POPULATE
// except for files in /proc and /dev/shm.
MmappedMemoryPtr<const SnapCorpus> LoadCorpusFromFile(const char* filename,
                                                      bool preload = true);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_SNAP_SNAP_CORPUS_UTIL_H_
