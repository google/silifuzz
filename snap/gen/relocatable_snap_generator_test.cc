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

#include "./snap/gen/relocatable_snap_generator.h"

#include <string.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/statusor.h"
#include "./common/memory_mapping.h"
#include "./common/memory_perms.h"
#include "./common/snapshot.h"
#include "./common/snapshot_test_util.h"
#include "./snap/gen/snap_generator.h"
#include "./snap/snap_relocator.h"
#include "./snap/snap_util.h"
#include "./snap/testing/snap_generator_test_lib.h"
#include "./snap/testing/snap_test_snapshots.h"
#include "./snap/testing/snap_test_types.h"
#include "./util/misc_util.h"
#include "./util/mmapped_memory_ptr.h"
#include "./util/platform.h"
#include "./util/testing/status_macros.h"
#include "./util/testing/status_matchers.h"

namespace silifuzz {
namespace {

using silifuzz::testing::IsOk;

// Test that undefined end state does not crash the generator.
TEST(RelocatableSnapGenerator, UndefinedEndState) {
  // Create an empty snapshot with no end state.
  TestSnapshots::Options create_options = TestSnapshots::Options::Default();
  create_options.force_undefined_state = true;
  Snapshot snapshot =
      TestSnapshots::Create(TestSnapshots::Type::kEmpty, create_options);

  SnapGenerator::Options snapify_options =
      SnapGenerator::Options::V2InputRunOpts();
  snapify_options.allow_undefined_end_state = true;
  ASSERT_OK_AND_ASSIGN(Snapshot snapified,
                       SnapGenerator::Snapify(snapshot, snapify_options));
  std::vector<Snapshot> corpus;
  corpus.push_back(std::move(snapified));
  auto relocatable = GenerateRelocatableSnaps(corpus);
  auto relocated_corpus = SnapRelocator::RelocateCorpus(std::move(relocatable));
  EXPECT_EQ(relocated_corpus->size, 1);
  EXPECT_EQ(relocated_corpus->elements[0]->id, snapshot.id());
}

TEST(RelocatableSnapGenerator, RoundTrip) {
  std::vector<Snapshot> corpus;
  {
    Snapshot snapshot =
        MakeSnapRunnerTestSnapshot(SnapRunnerTestType::kFirstSnapRunnerTest);

    ASSERT_OK_AND_ASSIGN(
        Snapshot snapified,
        SnapGenerator::Snapify(snapshot,
                               SnapGenerator::Options::V2InputRunOpts()));
    corpus.push_back(std::move(snapified));
  }

  auto relocatable = GenerateRelocatableSnaps(corpus);
  auto relocated_corpus = SnapRelocator::RelocateCorpus(std::move(relocatable));
  ASSERT_EQ(relocated_corpus->size, 1);
  auto snapshotFromSnap =
      SnapToSnapshot(*relocated_corpus->elements[0], CurrentPlatformId());
  ASSERT_OK(snapshotFromSnap);
  ASSERT_EQ(corpus[0], *snapshotFromSnap);
}

TEST(RelocatableSnapGenerator, AllRunnerTestSnaps) {
  // Generate relocatable snaps from runner test snaps.
  std::vector<Snapshot> snapified_corpus;
  const int first_runner_test_type =
      ToInt(SnapRunnerTestType::kFirstSnapRunnerTest);
  const int last_runner_test_type =
      ToInt(SnapRunnerTestType::kLastSnapRunnerTest);
  SnapGenerator::Options opts = SnapGenerator::Options::V2InputRunOpts();
  for (int type = first_runner_test_type; type <= last_runner_test_type;
       ++type) {
    Snapshot snapshot =
        MakeSnapRunnerTestSnapshot(static_cast<SnapRunnerTestType>(type));
    ASSERT_OK_AND_ASSIGN(Snapshot snapified,
                         SnapGenerator::Snapify(snapshot, opts));
    snapified_corpus.push_back(std::move(snapified));
  }

  auto relocatable_corpus = GenerateRelocatableSnaps(snapified_corpus);
  auto relocated_corpus =
      SnapRelocator::RelocateCorpus(std::move(relocatable_corpus));

  // Verify relocated Snap corpus is equivalent to the original Snapshots.
  ASSERT_EQ(snapified_corpus.size(), relocated_corpus->size);
  for (size_t i = 0; i < snapified_corpus.size(); ++i) {
    const Snapshot& snapshot = snapified_corpus[i];
    const Snap& snap = *relocated_corpus->elements[i];
    VerifyTestSnap(snapshot, snap, opts);
  }
}

// Test that duplicated byte data are merged to a single copy.
TEST(RelocatableSnapGenerator, DedupeMemoryBytes) {
  Snapshot snapshot =
      TestSnapshots::Create(TestSnapshots::Type::kEndsAsExpected);

  const size_t page_size = getpagesize();
  Snapshot::ByteData test_byte_data("This is a test");
  // Fill page with non repeating data. Otherwise run-length compression splits
  // this into 2 MemoryBytes objects and that will confuse the check for
  // de-duplication below.
  test_byte_data.reserve(page_size);
  for (size_t i = test_byte_data.size(); i < page_size; ++i) {
    test_byte_data.push_back(i % 256);
  }

  // Helper to add test_byte_data at `address`
  auto add_test_byte_data = [&](Snapshot::Address address) {
    const MemoryMapping mapping =
        MemoryMapping::MakeSized(address, page_size, MemoryPerms::R());
    ASSERT_OK(snapshot.can_add_memory_mapping(mapping));
    snapshot.add_memory_mapping(mapping);
    const Snapshot::MemoryBytes memory_bytes(address, test_byte_data);
    ASSERT_OK(snapshot.can_add_memory_bytes(memory_bytes));
    snapshot.add_memory_bytes(memory_bytes);
  };

  // Construct two memory bytes with identical byte data.
  const Snapshot::Address addr1 = 0x6502 * page_size;
  const Snapshot::Address addr2 = 0x8086 * page_size;
  add_test_byte_data(addr1);
  add_test_byte_data(addr2);

  ASSERT_OK_AND_ASSIGN(auto snapified,
                       SnapGenerator::Snapify(
                           snapshot, SnapGenerator::Options::V2InputRunOpts()));

  std::vector<Snapshot> snapified_corpus;
  snapified_corpus.push_back(std::move(snapified));

  auto relocatable_corpus = GenerateRelocatableSnaps(snapified_corpus);
  auto relocated_corpus =
      SnapRelocator::RelocateCorpus(std::move(relocatable_corpus));

  // Test byte data should appear twice in two MemoryBytes objects but
  // the array element addresses should be the same.
  ASSERT_EQ(relocated_corpus->size, 1);
  const Snap& snap = *relocated_corpus->elements[0];
  absl::flat_hash_set<const uint8_t*> addresses_seen;
  int times_seen = 0;
  for (const auto& memory_bytes : snap.memory_bytes) {
    if (!memory_bytes.repeating &&
        memory_bytes.size() == test_byte_data.size() &&
        memcmp(memory_bytes.data.byte_values.elements, test_byte_data.data(),
               test_byte_data.size()) == 0) {
      times_seen++;
      addresses_seen.insert(memory_bytes.data.byte_values.elements);
    }
  }
  EXPECT_EQ(times_seen, 2);
  EXPECT_EQ(addresses_seen.size(), 1);
}

}  // namespace
}  // namespace silifuzz
