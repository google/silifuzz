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

#include "./snap/snap_checksum.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "./snap/snap.h"
#include "./util/arch.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {
namespace {

uint32_t ChecksumHeader(SnapCorpusHeader& header) {
  CorpusChecksumCalculator checksum;
  checksum.AddData(&header, sizeof(header));
  return checksum.Checksum();
}

uint32_t ChecksumCorpusChunked(absl::string_view data, size_t chunk_size) {
  CorpusChecksumCalculator checksum;
  for (size_t i = 0; i < data.size(); i += chunk_size) {
    checksum.AddData(data.data() + i, std::min(chunk_size, data.size() - i));
  }
  return checksum.Checksum();
}

TEST(SnapChecksumTest, SkipsChecksumHole) {
  SnapCorpusHeader header;
  memset(&header, 0x5c, sizeof(header));
  uint32_t checksum = ChecksumHeader(header);

  // Make sure the checksum calculation doesn't depends on the checksum field.
  for (size_t i = 0; i < sizeof(header.checksum) * 8; ++i) {
    SnapCorpusHeader mutant;
    memcpy(&mutant, &header, sizeof(header));
    mutant.checksum ^= 1UL << i;
    EXPECT_EQ(checksum, ChecksumHeader(mutant)) << i;
  }
}

TEST(SnapChecksumTest, BeforeChecksumHole) {
  SnapCorpusHeader header;
  memset(&header, 0xc5, sizeof(header));
  uint32_t checksum = ChecksumHeader(header);

  static_assert(offsetof(SnapCorpusHeader, header_size) <
                offsetof(SnapCorpusHeader, checksum));

  // Make sure the checksum does catch bitflips before the checksum hole.
  for (size_t i = 0; i < sizeof(header.header_size) * 8; ++i) {
    SnapCorpusHeader mutant;
    memcpy(&mutant, &header, sizeof(header));
    mutant.header_size ^= 1UL << i;
    EXPECT_NE(checksum, ChecksumHeader(mutant)) << i;
  }
}

TEST(SnapChecksumTest, AfterChecksumHole) {
  SnapCorpusHeader header;
  memset(&header, 0xc5, sizeof(header));
  uint32_t checksum = ChecksumHeader(header);

  static_assert(offsetof(SnapCorpusHeader, num_bytes) >
                offsetof(SnapCorpusHeader, checksum));

  // Make sure the checksum does catch bitflips after the checksum hole.
  for (size_t i = 0; i < sizeof(header.num_bytes) * 8; ++i) {
    SnapCorpusHeader mutant;
    memcpy(&mutant, &header, sizeof(header));
    mutant.num_bytes ^= 1UL << i;
    EXPECT_NE(checksum, ChecksumHeader(mutant)) << i;
  }
}

TEST(SnapChecksumTest, ChecksumCorpusChunked) {
  absl::string_view data =
      "Blah blah blah needs to be big enough to be interesting so I'll keep "
      "typing on and on and on...";

  uint32_t checksum = ChecksumCorpusChunked(data, data.size());

  // In theory we should get the same checksum for the same underlying data, no
  // matter how we chunk it when calculating the checksum.
  for (size_t i = 1; i < 32; ++i) {
    EXPECT_EQ(checksum, ChecksumCorpusChunked(data, i)) << i;
  }
}

TEST(SnapChecksumTest, RegisterMemoryChecksumChecksum) {
  UContext<Host> ctx;
  UContextView<Host> view(ctx);

  memset(&ctx.fpregs, 0xaa, sizeof(ctx.fpregs));
  memset(&ctx.gregs, 0xbb, sizeof(ctx.gregs));

  uint32_t expect_fpregs_checksum = CalculateMemoryChecksum(*view.fpregs);
  uint32_t expect_gregs_checksum = CalculateMemoryChecksum(*view.gregs);

  SnapRegisterMemoryChecksum<Host> actual_checksum =
      CalculateRegisterMemoryChecksum(view);
  EXPECT_EQ(expect_fpregs_checksum, actual_checksum.fpregs_checksum);
  EXPECT_EQ(expect_gregs_checksum, actual_checksum.gregs_checksum);
}

}  // namespace
}  // namespace silifuzz
