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

#include "./snap/snap_corpus_util.h"

#include <memory>
#include <utility>
#include <vector>

#include "gtest/gtest.h"
#include "absl/status/statusor.h"
#include "./common/snapshot.h"
#include "./common/snapshot_test_enum.h"
#include "./snap/gen/relocatable_snap_generator.h"
#include "./snap/gen/snap_generator.h"
#include "./snap/testing/snap_test_snapshots.h"
#include "./util/arch.h"
#include "./util/file_util.h"
#include "./util/mmapped_memory_ptr.h"
#include "./util/path_util.h"
#include "./util/testing/status_macros.h"

namespace silifuzz {
namespace {
using ::testing::UnitTest;

TEST(SnapCorpusUtilTest, LoadCorpusFromFile) {
  // Generate relocatable snaps from runner test snaps.
  std::vector<Snapshot> snapified_corpus;
  {
    Snapshot snapshot =
        MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kEndsAsExpected);
    SnapifyOptions opts =
        SnapifyOptions::V2InputRunOpts(snapshot.architecture_id());
    ASSERT_OK_AND_ASSIGN(Snapshot snapified, Snapify(snapshot, opts));
    snapified_corpus.emplace_back(std::move(snapified));
  }

  MmappedMemoryPtr<char> buffer =
      GenerateRelocatableSnaps(Host::architecture_id, snapified_corpus);
  auto tmpfile = CreateTempFile(
      UnitTest::GetInstance()->current_test_info()->test_case_name());
  ASSERT_TRUE(
      SetContents(*tmpfile, {reinterpret_cast<const char*>(buffer.get()),
                             MmappedMemorySize(buffer)}));
  auto loaded_corpus = LoadCorpusFromFile<Host>(tmpfile->c_str());
  EXPECT_EQ(loaded_corpus->snaps.size, 1);
  EXPECT_EQ(loaded_corpus->snaps.at(0)->id, snapified_corpus[0].id());
}

TEST(SnapCorpusUtilTest, LoadEmptyCorpus) {
  std::vector<Snapshot> snapified_corpus;
  MmappedMemoryPtr<char> buffer =
      GenerateRelocatableSnaps(Host::architecture_id, snapified_corpus);
  auto tmpfile = CreateTempFile(
      UnitTest::GetInstance()->current_test_info()->test_case_name());
  ASSERT_TRUE(
      SetContents(*tmpfile, {reinterpret_cast<const char*>(buffer.get()),
                             MmappedMemorySize(buffer)}));
  EXPECT_EQ(LoadCorpusFromFile<Host>(tmpfile->c_str())->snaps.size, 0);
}

}  // namespace
}  // namespace silifuzz
