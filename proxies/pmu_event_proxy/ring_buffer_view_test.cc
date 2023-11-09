// Copyright 2023 The SiliFuzz Authors.
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

#include "./proxies/pmu_event_proxy/ring_buffer_view.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <numeric>

#include "gtest/gtest.h"

namespace silifuzz {
namespace {

TEST(RingBufferView, BasicTest) {
  using DataType = uint32_t;
  constexpr size_t kAmountOfData = 4;  // must of a power of 2.
  DataType source[kAmountOfData];
  constexpr DataType kFirst = 0xdeadbeef;
  std::iota(source, source + kAmountOfData, kFirst);

  // Copy source into a ring buffer so that it is unaligned and wraps around.
  const size_t offset = sizeof(source) / 2 + 1;
  char ring_buffer[sizeof(source)];
  const size_t first_part_size = sizeof(source) - offset;
  const size_t second_part_size = offset;
  memcpy(ring_buffer + offset, source, first_part_size);
  memcpy(ring_buffer, reinterpret_cast<const char*>(source) + first_part_size,
         second_part_size);

  // Create a view covering all data.
  RingBufferView view(offset + sizeof(source), offset, ring_buffer,
                      sizeof(ring_buffer));
  // Save view for Peek test.
  RingBufferView view2(view);

  // Test Read().
  DataType target[kAmountOfData];
  for (size_t i = 0; i < kAmountOfData; ++i) {
    EXPECT_EQ(view.size(), sizeof(source) - i * sizeof(DataType));
    view.Read(target[i]);
    EXPECT_EQ(target[i], source[i]);
    EXPECT_EQ(view.size(), sizeof(source) - (i + 1) * sizeof(DataType));
  }
  EXPECT_EQ(view.size(), 0);

  // Test Peek() & Skip().
  memset(target, 0xff, sizeof(target));
  for (size_t i = 0; i < kAmountOfData; ++i) {
    size_t size_before = view2.size();
    view2.Peek(target[i]);
    EXPECT_EQ(view2.size(), size_before);
    EXPECT_EQ(target[i], source[i]);
    view2.Skip(sizeof(DataType));
    EXPECT_EQ(view2.size(), size_before - sizeof(DataType));
  }
  EXPECT_EQ(view2.size(), 0);
}

TEST(RingBufferView, VirtualOffsetOverflow) {
  const size_t tail = ~0;
  const size_t head = tail + sizeof(uint64_t);
  char buffer[sizeof(uint64_t) * 2];
  memset(buffer, 0, sizeof(buffer));
  RingBufferView view(head, tail, buffer, sizeof(buffer));
  RingBufferView view2(view);

  // These should not crash.
  uint64_t n;
  view.Peek(n);
  view.Skip(sizeof(n));
  view2.Read(n);
}

}  // namespace
}  // namespace silifuzz
