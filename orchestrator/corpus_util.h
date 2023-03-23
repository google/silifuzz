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

#ifndef THIRD_PARTY_SILIFUZZ_ORCHESTRATOR_CORPUS_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_ORCHESTRATOR_CORPUS_UTIL_H_
#include <string>
#include <vector>

// Utility functions for the orchestrator to load corpora in shared memory.

#include "absl/status/statusor.h"
#include "absl/strings/cord.h"
#include "absl/strings/string_view.h"
#include "./util/owned_file_descriptor.h"

namespace silifuzz {

// Reads an lzma compressed file into memory.  Returns its contents in a cord or
// an error status.
absl::StatusOr<absl::Cord> ReadXzipFile(const std::string& path);

// Creates a mem file and writes `contents` to it, and then seals it
// to protect it from modification. The `name` for the file is optional and is
// purely for debugging. WriteSharedMemoryFile() always creates a new file
// for each call regardless of `name`.  See man page of memfd_create() for
// details.
//
// RETURNS a file descriptor for the file, which remains opened at return.
//
// Caller owns the returned descriptor.
absl::StatusOr<OwnedFileDescriptor> WriteSharedMemoryFile(
    const absl::Cord& contents, absl::string_view = "SharedMemoryFile");

// Loads a compressed relocatable Snap corpus in `path` and returns an owned
// file descriptor of a temp file containing uncompressed corpus contents in
// RAM. LoadCorpus determins the decompression algorithm to use based on
// suffix of `path`. Currently only .gz and .xz are recognized.
absl::StatusOr<OwnedFileDescriptor> LoadCorpus(const std::string& path);

struct InMemoryCorpora {
  // File descriptors returned by LoadCorpora() below, in the same order
  // as their corresponding corpus paths in
  std::vector<OwnedFileDescriptor> file_descriptors;

  // Paths in /proc file system to access the elements of file_descriptors
  // above. Paths are in the same order as corresponding file descriptors.
  std::vector<std::string> file_descriptor_paths;

  // Shard names corresponding to the file_descriptors above. The names are in
  // the same order as the descriptors.
  std::vector<std::string> shard_names;
};

// Reads and decompresses gzipped relocatable Snap corpora whose paths are in
// `corpus_path`. Contents of each corpus are written in a file created in RAM.
//
// RETURNS an InMemoryCorpora struct contaning a vector of owned file
// descriptors and a vector of paths or an error status. See above for details
// about InMemoryCorpora.
//
// REQUIRES: corpus_paths not empty.
absl::StatusOr<InMemoryCorpora> LoadCorpora(
    const std::vector<std::string>& corpus_paths);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_ORCHESTRATOR_CORPUS_UTIL_H_
