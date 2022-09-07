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

#include "./snap/gen/relocatable_data_block.h"

#include <cstddef>
#include <cstdint>

#include "gtest/gtest.h"

namespace silifuzz {
namespace {

using Address = RelocatableDataBlock::Address;

TEST(RelocatableDataBlock, Construction) {
  RelocatableDataBlock block;
  EXPECT_EQ(block.required_alignment(), 1);
  EXPECT_EQ(block.size(), 0);
  EXPECT_EQ(block.contents(), nullptr);
  EXPECT_EQ(block.load_address(), RelocatableDataBlock::kInvalidAddress);
}

TEST(RelocatableDataBlock, Allocate) {
  RelocatableDataBlock block;
  constexpr size_t kBufferSizeInUint64 = 20;
  uint64_t buffer[kBufferSizeInUint64];
  block.set_contents(reinterpret_cast<char*>(buffer), sizeof(buffer));
  auto ref = block.Allocate(5, 2);
  EXPECT_EQ(ref.relocatable_data_block(), &block);
  EXPECT_EQ(ref.byte_offset(), 0);
  EXPECT_EQ(block.size(), 5);
  EXPECT_EQ(block.required_alignment(), 2);

  ref = block.Allocate(2, 1);
  EXPECT_EQ(block.size(), 7);
  EXPECT_EQ(block.required_alignment(), 2);
}

TEST(RelocatableDataBlock, AllocateSubBlock) {
  RelocatableDataBlock block;
  auto ref = block.Allocate(5, 2);

  RelocatableDataBlock sub_block;
  ref = sub_block.Allocate(7, 4);

  ref = block.Allocate(sub_block);
  EXPECT_EQ(ref.byte_offset() % sub_block.required_alignment(), 0);
  EXPECT_EQ(block.size(), ref.byte_offset() + sub_block.size());
}

TEST(RelocatableDataBlock, AllocateObjectOfType) {
  RelocatableDataBlock block;
  auto ref = block.Allocate(5, 2);

  ref = block.AllocateObjectsOfType<uint64_t>(3);
  EXPECT_EQ(ref.byte_offset() % sizeof(uint64_t), 0);
  EXPECT_EQ(block.required_alignment(), sizeof(uint64_t));
  EXPECT_EQ(block.size(), 32);
}

TEST(RelocatableDataBlock, ResetSizeAndAlignment) {
  RelocatableDataBlock block;
  constexpr Address kLoadAddress = 0x1234000;
  char TestBuffer[20];
  block.set_contents(TestBuffer, sizeof(TestBuffer));
  block.set_load_address(kLoadAddress);
  block.Allocate(5, 2);
  EXPECT_EQ(block.size(), 5);
  EXPECT_EQ(block.required_alignment(), 2);

  block.ResetSizeAndAlignment();

  // Check that only size and alignment are cleared.
  EXPECT_EQ(block.size(), 0);
  EXPECT_EQ(block.required_alignment(), 1);
  EXPECT_EQ(block.contents(), TestBuffer);
  EXPECT_EQ(block.load_address(), kLoadAddress);
}

TEST(RelocatableDataBlockRef, LoadAddress) {
  uint64_t contents[16];
  RelocatableDataBlock block;
  auto ref = block.AllocateObjectsOfType<uint64_t>(3);
  auto ref2 = block.AllocateObjectsOfType<uint64_t>(1);
  block.set_load_address(0);
  EXPECT_EQ(ref.load_address(), 0);
  EXPECT_EQ(ref2.load_address(), 3 * sizeof(uint64_t));

  // Set load address to &contents so that load address is the
  // same as the address inside the test.
  block.set_load_address(reinterpret_cast<Address>(&contents));
  EXPECT_EQ(ref2.load_address_as_pointer_of<uint64_t>(), &contents[3]);
}

TEST(RelocatableDataBlockRef, Contents) {
  uint64_t contents[16];
  RelocatableDataBlock block;
  auto ref = block.AllocateObjectsOfType<uint64_t>(3);
  auto ref2 = block.AllocateObjectsOfType<uint64_t>(1);
  block.set_contents(reinterpret_cast<char*>(contents), sizeof(contents));
  EXPECT_EQ(ref.contents(), reinterpret_cast<char*>(&contents[0]));
  EXPECT_EQ(ref2.contents(), reinterpret_cast<char*>(&contents[3]));
  EXPECT_EQ(ref.contents_as_pointer_of<uint64_t>(), &contents[0]);
  EXPECT_EQ(ref2.contents_as_pointer_of<uint64_t>(), &contents[3]);
}

TEST(RelocatableDataBlockRef, AddOperator) {
  RelocatableDataBlock block;
  auto ref = block.Allocate(12, 1);
  ref = block.Allocate(1, 1);

  constexpr int64_t kForwardAdjustment = 3;
  auto ref2 = ref + kForwardAdjustment;
  EXPECT_EQ(ref2.relocatable_data_block(), &block);
  EXPECT_EQ(ref2.byte_offset(), ref.byte_offset() + kForwardAdjustment);
}

}  // namespace
}  // namespace silifuzz
