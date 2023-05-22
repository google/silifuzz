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

#include <cstdint>
#include <cstring>
#include <limits>
#include <utility>
#include <vector>

#include "gtest/gtest.h"
#include "absl/status/statusor.h"
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
  Snapshot snapshot =
      MakeSnapRunnerTestSnapshot<Host>(TestSnapshot::kEndsAsExpected);
  EXPECT_EQ(Host::architecture_id, snapshot.architecture_id());
  SnapifyOptions opts =
      SnapifyOptions::V2InputRunOpts(snapshot.architecture_id());
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
    corpus_ = reinterpret_cast<SnapCorpus<Host>*>(relocatable_.get());
  }

  void ExpectRelocationResultIs(SnapRelocatorError expected_error) {
    SnapRelocatorError error;
    MmappedMemoryPtr<const SnapCorpus<Host>> corpus_mmaped_memory_ptr =
        SnapRelocator<Host>::RelocateCorpus(std::move(relocatable_), &error);
    EXPECT_EQ(error, expected_error);
  }

  MmappedMemoryPtr<char> relocatable_;  // A relocatable corpus for testing.
  SnapCorpus<Host>* corpus_;  // relocatable_ cast as a SnapCorpus pointer.
};

TEST_F(SnapRelocatorTest, CanRelocateGoodCorpus) {
  ExpectRelocationResultIs(SnapRelocatorError::kOk);
}

TEST_F(SnapRelocatorTest, UnalignedSnapPointer) {
  const Snap<Host>* const bad_pointer = reinterpret_cast<const Snap<Host>*>(
      reinterpret_cast<uintptr_t>(corpus_->snaps.elements) + 1);
  memcpy(&corpus_->snaps.elements, &bad_pointer,
         sizeof(corpus_->snaps.elements));
  ExpectRelocationResultIs(SnapRelocatorError::kAlignment);
}

TEST_F(SnapRelocatorTest, OutOfBoundPointer) {
  // This moves the elements out of the mmapped area.
  const Snap<Host>* const bad_pointer =
      reinterpret_cast<const Snap<Host>*>(MmappedMemorySize(relocatable_));
  memcpy(&corpus_->snaps.elements, &bad_pointer,
         sizeof(corpus_->snaps.elements));
  ExpectRelocationResultIs(SnapRelocatorError::kOutOfBound);
}

TEST_F(SnapRelocatorTest, ArraySizeOutOfBound) {
  // This pushes the last element out of the mmapped area.
  corpus_->snaps.size = MmappedMemorySize(relocatable_);
  ExpectRelocationResultIs(SnapRelocatorError::kOutOfBound);
}

TEST_F(SnapRelocatorTest, ArraySizeOverflow) {
  // Overflow in multiplication.
  corpus_->snaps.size = std::numeric_limits<size_t>::max();
  ExpectRelocationResultIs(SnapRelocatorError::kOutOfBound);
}

TEST_F(SnapRelocatorTest, ArrayElementAddressOverflow) {
  // Overflow in array element offset computation.
  corpus_->snaps.size =
      std::numeric_limits<size_t>::max() / sizeof(corpus_->snaps.elements[0]);
  ExpectRelocationResultIs(SnapRelocatorError::kOutOfBound);
}

}  // namespace

}  // namespace silifuzz
