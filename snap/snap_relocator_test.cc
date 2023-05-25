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

template <typename Arch>
absl::StatusOr<MmappedMemoryPtr<char>> GetTestRelocatableCorpus() {
  // Generate relocatable snaps from runner test snaps.
  Snapshot snapshot =
      MakeSnapRunnerTestSnapshot<Arch>(TestSnapshot::kEndsAsExpected);
  EXPECT_EQ(Arch::architecture_id, snapshot.architecture_id());
  SnapifyOptions opts =
      SnapifyOptions::V2InputRunOpts(snapshot.architecture_id());
  auto snapified_or = Snapify(snapshot, opts);
  RETURN_IF_NOT_OK(snapified_or.status());

  std::vector<Snapshot> snapified_corpus;
  snapified_corpus.emplace_back(std::move(snapified_or.value()));

  MmappedMemoryPtr<char> buffer =
      GenerateRelocatableSnaps(Arch::architecture_id, snapified_corpus);
  return buffer;
}

template <typename Arch>
class SnapRelocatorTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_OK_AND_ASSIGN(relocatable_, GetTestRelocatableCorpus<Arch>());
    corpus_ = reinterpret_cast<SnapCorpus<Arch>*>(relocatable_.get());
  }

  void ExpectRelocationResultIs(SnapRelocatorError expected_error) {
    SnapRelocatorError error;
    MmappedMemoryPtr<const SnapCorpus<Arch>> corpus_mmaped_memory_ptr =
        SnapRelocator<Arch>::RelocateCorpus(std::move(relocatable_), &error);
    EXPECT_EQ(error, expected_error);
  }

  MmappedMemoryPtr<char> relocatable_;  // A relocatable corpus for testing.
  SnapCorpus<Arch>* corpus_;  // relocatable_ cast as a SnapCorpus pointer.
};

using arch_typelist = ::testing::Types<ALL_ARCH_TYPES>;
TYPED_TEST_SUITE(SnapRelocatorTest, arch_typelist);

TYPED_TEST(SnapRelocatorTest, CanRelocateGoodCorpus) {
  this->ExpectRelocationResultIs(SnapRelocatorError::kOk);
}

TYPED_TEST(SnapRelocatorTest, UnalignedSnapPointer) {
  SnapCorpus<TypeParam>* corpus = this->corpus_;
  const Snap<TypeParam>* const bad_pointer =
      reinterpret_cast<const Snap<TypeParam>*>(
          reinterpret_cast<uintptr_t>(corpus->snaps.elements) + 1);
  memcpy(&corpus->snaps.elements, &bad_pointer, sizeof(corpus->snaps.elements));
  this->ExpectRelocationResultIs(SnapRelocatorError::kAlignment);
}

TYPED_TEST(SnapRelocatorTest, OutOfBoundPointer) {
  SnapCorpus<TypeParam>* corpus = this->corpus_;
  // This moves the elements out of the mmapped area.
  const Snap<TypeParam>* const bad_pointer =
      reinterpret_cast<const Snap<TypeParam>*>(
          MmappedMemorySize(this->relocatable_));
  memcpy(&corpus->snaps.elements, &bad_pointer, sizeof(corpus->snaps.elements));
  this->ExpectRelocationResultIs(SnapRelocatorError::kOutOfBound);
}

TYPED_TEST(SnapRelocatorTest, ArraySizeOutOfBound) {
  // This pushes the last element out of the mmapped area.
  this->corpus_->snaps.size = MmappedMemorySize(this->relocatable_);
  this->ExpectRelocationResultIs(SnapRelocatorError::kOutOfBound);
}

TYPED_TEST(SnapRelocatorTest, ArraySizeOverflow) {
  // Overflow in multiplication.
  this->corpus_->snaps.size = std::numeric_limits<size_t>::max();
  this->ExpectRelocationResultIs(SnapRelocatorError::kOutOfBound);
}

TYPED_TEST(SnapRelocatorTest, ArrayElementAddressOverflow) {
  SnapCorpus<TypeParam>* corpus = this->corpus_;
  // Overflow in array element offset computation.
  corpus->snaps.size =
      std::numeric_limits<size_t>::max() / sizeof(corpus->snaps.elements[0]);
  this->ExpectRelocationResultIs(SnapRelocatorError::kOutOfBound);
}

}  // namespace

}  // namespace silifuzz
