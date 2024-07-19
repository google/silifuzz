// Copyright 2024 The SiliFuzz Authors.
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

#include "./util/aarch64/sve.h"

#include <cstddef>

#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/nolibc_gunit.h"

namespace silifuzz {
namespace {

TEST(SveTest, ValidSveRegisterLengths) {
  if (!SveIsSupported()) {
    GTEST_SKIP();
  }
  size_t z_len = SveGetCurrentVectorLength();
  LOG_INFO("SVE Z register length in bytes: ", IntStr(z_len));
  CHECK_EQ(z_len % kSveZRegSizeAlignmentBytes, 0);
  CHECK_NE(z_len, 0);
  CHECK_LE(z_len, kSveZRegMaxSizeBytes);

  size_t p_len = SveGetPredicateLength();
  CHECK_EQ(p_len * kSvePRegSizeZRegFactor, z_len);
  CHECK_LE(p_len, kSvePRegMaxSizeBytes);
}

TEST(SveTest, SetSveVectorLength) {
  if (!SveIsSupported()) {
    GTEST_SKIP();
  }
  size_t original_z_len = SveGetCurrentVectorLength();

  size_t min_z_len = SveSetCurrentVectorLength(kSveZRegSizeAlignmentBytes);
  CHECK_EQ(min_z_len, kSveZRegSizeAlignmentBytes);

  // Note: kSveZRegMaxSizeBytes (0x100) is different than SVE_VL_MAX (0x2000).
  // kSveZRegMaxSizeBytes represents the maximum possible vector according to
  // the SVE specification. SVE_VL_MAX is a Linux future-proofed vector length.
  //
  // If the specified vector length is greater than the max current vector
  // length, the value set should be capped to the actual maximum.
  size_t max_z_len_0 = SveSetMaxVectorLength();
  size_t max_z_len_1 = SveSetCurrentVectorLength(kSveZRegMaxSizeBytes);
  CHECK_EQ(max_z_len_0, max_z_len_1);

  size_t restored_original_z_len = SveSetCurrentVectorLength(original_z_len);
  CHECK_EQ(original_z_len, restored_original_z_len);
}

}  // namespace
}  // namespace silifuzz

// ========================================================================= //

NOLIBC_TEST_MAIN({
  RUN_TEST(SveTest, ValidSveRegisterLengths);
  RUN_TEST(SveTest, SetSveVectorLength);
})
