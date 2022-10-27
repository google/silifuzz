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

#include "./tools/simple_fix_tool.h"

#include <fcntl.h>
#include <sys/mman.h>

#include <filesystem>  // NOLINT(build/c++17)
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/cleanup/cleanup.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "external/centipede/blob_file.h"
#include "./snap/snap_relocator.h"
#include "./tool_libs/simple_fix_tool_counters.h"
#include "./util/checks.h"
#include "./util/mmapped_memory_ptr.h"
#include "./util/path_util.h"
#include "./util/testing/status_macros.h"
#include "./util/testing/status_matchers.h"

using centipede::DefaultBlobFileAppenderFactory;
using testing::SizeIs;
using testing::UnorderedElementsAre;

namespace silifuzz {

namespace {
std::string GetNOP() {
  return std::string("\x90");  // x86 NOP.
}

absl::StatusOr<std::string> CreateTempBlobFile(
    std::vector<std::string>& blobs) {
  auto filename_or = CreateTempFile("SimpleFixToolTest");
  RETURN_IF_NOT_OK(filename_or.status());
  std::string filename = filename_or.value();
  absl::Cleanup file_deleter =
      absl::MakeCleanup([filename] { std::filesystem::remove(filename); });
  auto writer = DefaultBlobFileAppenderFactory();
  RETURN_IF_NOT_OK(writer->Open(filename));
  for (const auto& blob : blobs) {
    absl::Span<const uint8_t> s(reinterpret_cast<const uint8_t*>(blob.data()),
                                blob.size());
    RETURN_IF_NOT_OK(writer->Append(s));
  }
  RETURN_IF_NOT_OK(writer->Close());
  std::move(file_deleter).Cancel();
  return filename;
}

}  // namespace

namespace fix_tool_internal {
namespace {

// Test that we can read from multiple blob inputs and de-dupe.
TEST(SimpleFixTool, ReadUniqueCentipedeBlobs) {
  // Create 2 blobs file that contains duplicates.

  std::vector<std::string> blobs_1{"one", "two"};
  ASSERT_OK_AND_ASSIGN(std::string blob_file_1, CreateTempBlobFile(blobs_1));
  absl::Cleanup delete_file_1 = absl::MakeCleanup(
      [blob_file_1] { std::filesystem::remove(blob_file_1); });

  std::vector<std::string> blobs_2{"two", "three", "three"};
  ASSERT_OK_AND_ASSIGN(std::string blob_file_2, CreateTempBlobFile(blobs_2));
  absl::Cleanup delete_file_2 = absl::MakeCleanup(
      [blob_file_2] { std::filesystem::remove(blob_file_2); });

  const std::vector inputs{blob_file_1, blob_file_2};
  SimpleFixToolCounters counters;
  std::vector<std::string> blobs = ReadUniqueCentipedeBlobs(inputs, &counters);
  EXPECT_THAT(blobs, SizeIs(3));
  EXPECT_THAT(blobs, UnorderedElementsAre("one", "two", "three"));
}

// Test snapshot making.
TEST(SimpleFixTool, MakeSnapshotsFromBlobs) {
  // Create Blobs with NOP sequences of different lengths.
  const std::string nop = GetNOP();
  constexpr int kNumBlobs = 10;
  std::string insns;
  std::vector<std::string> blobs;
  for (int i = 0; i < kNumBlobs; ++i, insns += nop) {
    blobs.push_back(insns);
  }

  SimpleFixToolCounters counters;
  std::vector<Snapshot> made_snapshots =
      MakeSnapshotsFromBlobs({}, blobs, &counters);
  EXPECT_THAT(made_snapshots, SizeIs(kNumBlobs));
}

}  // namespace
}  // namespace fix_tool_internal

namespace {

// End-to-end test from blobs to a relocatable corpus.
TEST(SimpleFixTool, FixCorpus) {
  constexpr int kNumBlobFiles = 3;
  constexpr int kNumBlobsPerFile = 4;

  std::string insns;
  std::vector<std::string> blob_files;
  absl::Cleanup remove_blob_files = absl::MakeCleanup([&blob_files] {
    for (const auto& blob_file : blob_files) {
      std::filesystem::remove(blob_file);
    }
  });

  // Generate NOP sequences of different lengths. These will get different
  // snapshot IDs.
  const std::string nop = GetNOP();
  for (int i = 0; i < kNumBlobFiles; ++i) {
    std::vector<std::string> blobs;
    for (int j = 0; j < kNumBlobsPerFile; ++j, insns += nop) {
      blobs.push_back(insns);
    }
    ASSERT_OK_AND_ASSIGN(auto blob_file, CreateTempBlobFile(blobs));
    blob_files.push_back(blob_file);
  }

  absl::string_view tmpdir = Dirname(blob_files[0]);
  const std::string output_path_prefix =
      absl::StrCat(tmpdir, "/simple_fix_tool_test-", getpid());
  constexpr int kNumShards = 4;
  fix_tool_internal::SimpleFixToolCounters counters;
  FixupCorpus({}, blob_files, output_path_prefix, kNumShards, &counters);

  auto shard_file_name = [&output_path_prefix](int i) {
    return absl::StrFormat("%s.%05d", output_path_prefix, i);
  };

  absl::Cleanup delete_output_files = absl::MakeCleanup([&shard_file_name] {
    for (int i = 0; i < kNumShards; ++i) {
      std::filesystem::remove(shard_file_name(i));
    }
  });

  // Read relocatable corpus
  int num_snaps = 0;
  for (int i = 0; i < kNumShards; ++i) {
    int fd = open(shard_file_name(i).c_str(), O_RDONLY);
    ASSERT_NE(fd, -1);
    off_t file_size = std::filesystem::file_size(shard_file_name(i));
    ASSERT_NE(file_size, -1);
    void* relocatable =
        mmap(nullptr, file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    ASSERT_NE(relocatable, MAP_FAILED);
    auto mapped = MakeMmappedMemoryPtr<char>(
        reinterpret_cast<char*>(relocatable), file_size);
    EXPECT_EQ(close(fd), 0);
    SnapRelocator::Error error;
    MmappedMemoryPtr<const Snap::Corpus> corpus =
        SnapRelocator::RelocateCorpus(std::move(mapped), &error);
    ASSERT_TRUE(error == SnapRelocator::Error::kOk);
    num_snaps += corpus->size;
  }

  // Snapshots are NOP sequences of different lengths.  There should not be any
  // memory conflicts. We expect them to be all present in the final relocatable
  // corpus.
  EXPECT_EQ(num_snaps, kNumBlobFiles * kNumBlobsPerFile);
}
}  // namespace

}  // namespace silifuzz
