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

#include "./snap/snap_relocator.h"

#include <cstring>
#include <limits>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "./common/snapshot.h"
#include "./snap/gen/relocatable_snap_generator.h"
#include "./snap/gen/snap_generator.h"
#include "./snap/snap.h"
#include "./snap/testing/snap_test_snapshots.h"
#include "./snap/testing/snap_test_types.h"
#include "./util/mmapped_memory_ptr.h"
#include "./util/testing/status_macros.h"

namespace silifuzz {
namespace {

absl::StatusOr<MmappedMemoryPtr<char>> GetTestRelocatableCorpus() {
  // Generate relocatable snaps from runner test snaps.
  SnapifyOptions opts = SnapifyOptions::V2InputRunOpts();
  Snapshot snapshot = MakeSnapRunnerTestSnapshot(TestSnapshot::kEndsAsExpected);
  auto snapified_or = Snapify(snapshot, opts);
  RETURN_IF_NOT_OK(snapified_or.status());

  std::vector<Snapshot> snapified_corpus;
  snapified_corpus.emplace_back(std::move(snapified_or.value()));

  MmappedMemoryPtr<char> buffer =
      GenerateRelocatableSnaps(Host::architecture_id, snapified_corpus);
  return buffer;
}

class SnapRelocatorTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK_AND_ASSIGN(relocatable_, GetTestRelocatableCorpus());
    corpus_ = reinterpret_cast<SnapCorpus*>(relocatable_.get());
  }

  void ExpectRelocationResultIs(SnapRelocator::Error expected_error) {
    SnapRelocator::Error error;
    MmappedMemoryPtr<const SnapCorpus> corpus_mmaped_memory_ptr =
        SnapRelocator::RelocateCorpus(std::move(relocatable_), &error);
    EXPECT_EQ(error, expected_error);
  }

  MmappedMemoryPtr<char> relocatable_;  // A relocatable corpus for testing.
  SnapCorpus* corpus_;  // relocatable_ cast as a SnapCorpus pointer.
};

TEST_F(SnapRelocatorTest, CanRelocateGoodCorpus) {
  ExpectRelocationResultIs(SnapRelocator::Error::kOk);
}

TEST_F(SnapRelocatorTest, UnalignedSnapPointer) {
  const Snap* const bad_pointer = reinterpret_cast<const Snap*>(
      reinterpret_cast<uintptr_t>(corpus_->snaps.elements) + 1);
  memcpy(&corpus_->snaps.elements, &bad_pointer,
         sizeof(corpus_->snaps.elements));
  ExpectRelocationResultIs(SnapRelocator::Error::kAlignment);
}

TEST_F(SnapRelocatorTest, OutOfBoundPointer) {
  // This moves the elements out of the mmapped area.
  const Snap* const bad_pointer =
      reinterpret_cast<const Snap*>(MmappedMemorySize(relocatable_));
  memcpy(&corpus_->snaps.elements, &bad_pointer,
         sizeof(corpus_->snaps.elements));
  ExpectRelocationResultIs(SnapRelocator::Error::kOutOfBound);
}

TEST_F(SnapRelocatorTest, ArraySizeOutOfBound) {
  // This pushes the last element out of the mmapped area.
  corpus_->snaps.size = MmappedMemorySize(relocatable_);
  ExpectRelocationResultIs(SnapRelocator::Error::kOutOfBound);
}

TEST_F(SnapRelocatorTest, ArraySizeOverflow) {
  // Overflow in multiplication.
  corpus_->snaps.size = std::numeric_limits<size_t>::max();
  ExpectRelocationResultIs(SnapRelocator::Error::kOutOfBound);
}

TEST_F(SnapRelocatorTest, ArrayElementAddressOverflow) {
  // Overflow in array element offset computation.
  corpus_->snaps.size =
      std::numeric_limits<size_t>::max() / sizeof(corpus_->snaps.elements[0]);
  ExpectRelocationResultIs(SnapRelocator::Error::kOutOfBound);
}

}  // namespace

}  // namespace silifuzz
