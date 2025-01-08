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
#include <cstdint>
#include <string>
#include <vector>

// Utility functions for the orchestrator to load corpora in shared memory.

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/cord.h"
#include "absl/strings/string_view.h"
#include "./util/owned_file_descriptor.h"

namespace silifuzz {

struct InMemoryShard {
  // A file descriptor holding the complete, uncompressed corpus shard.
  OwnedFileDescriptor file_descriptor;

  // Paths in /proc file system to access the file_descriptor above.
  std::string file_path;

  // Printable name of the shard.
  // This should be the base file name of the shard without the directory and
  // with any compression extension stripped off (".xz", etc).
  std::string name;

  // The bytes of the SnapCorpusHeader at the start of the file.
  // Preserved so we can validate it.
  // May be too small if the file is too small.
  std::string header_bytes;

  // The size of the uncompressed corpus shard file, in bytes.
  uint64_t file_size;

  // The checksum of the file.
  uint32_t checksum;
};

struct InMemoryCorpora {
  std::vector<InMemoryShard> shards;
};

// Check that all the shards look OK.
// The header seems consistent, the checksum is correct, etc.
absl::Status ValidateCorpus(const InMemoryCorpora& corpora);

// Checked that a single shard looks OK.
// Exposed for testing.
absl::Status ValidateShard(const InMemoryShard& shard);

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
// RAM. LoadCorpus determines the decompression algorithm to use based on
// suffix of `path`. Currently only .xz is recognized.
absl::StatusOr<InMemoryShard> LoadCorpus(const std::string& path);

// Reads and decompresses gzipped relocatable Snap corpora whose paths are in
// `corpus_path`. Contents of each corpus are written in a file created in RAM.
//
// RETURNS an InMemoryCorpora struct containing a vector of owned file
// descriptors and a vector of paths or an error status. See above for details
// about InMemoryCorpora.
//
// REQUIRES: corpus_paths not empty.
absl::StatusOr<InMemoryCorpora> LoadCorpora(
    const std::vector<std::string>& corpus_paths);

// Given the decompresses gzipped relocatable Snap corpora whose paths are in
// `corpus_path`, estimates the size of the largest corpus in MB.
//
// This function first finds the possibly largest corpus file by checking the
// compressed file size. Then it is decompressed and loaded into memory, and its
// size is returned.
//
// This function assumes that all the corpora are compressed with the same
// settings. If the corpora is a mix of different compression settings, the
// result may be inaccurate.
//
// REQUIRES: corpus_paths not empty.
absl::StatusOr<uint64_t> EstimateLargestCorpusSizeMB(
    const std::vector<std::string>& corpus_paths);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_ORCHESTRATOR_CORPUS_UTIL_H_
