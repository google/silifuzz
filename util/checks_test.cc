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

#if !defined(SILIFUZZ_BUILD_FOR_NOLIBC)
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#endif
#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/nolibc_gunit.h"

// ========================================================================= //

// TODO(ksteuck): [test] We should also golden-matcher-test the logging output
// (in nolibc mode as well).

namespace silifuzz {
namespace {

TEST(ChecksTest, Log) {
  LOG_ERROR("error ", IntStr(11));
  LOG_INFO("info ", 22);
  CHECK(VLOG_IS_ON(-10));
  CHECK(!VLOG_IS_ON(10));
  VLOG_INFO(10, "vlog off ", 33);
  VLOG_INFO(-10, "vlog on ", IntStr(33));
  LOG_ERROR_IF(false, "error if off ", 44);
  LOG_ERROR_IF(true, "error if on ", 44);
  LOG_INFO_IF(false, "info if off ", 55);
  LOG_INFO_IF(true, "info if on ", IntStr(55));
  VLOG_INFO_IF(true, 10, "vlog if on off ", 66);
  VLOG_INFO_IF(false, 10, "vlog if off off ", 66);
  VLOG_INFO_IF(true, -10, "vlog if on on ", 66);
  VLOG_INFO_IF(false, -10, "vlog if off on ", 66);

  EXPECT_DEATH_IF_SUPPORTED({ LOG_FATAL("fatal ", IntStr(77)); }, "fatal 77");
  LOG_FATAL_IF(false, "fatal if off ", 88);
  EXPECT_DEATH_IF_SUPPORTED(
      { LOG_FATAL_IF(true, "fatal if on ", 88); }, "fatal if on 88");
  if (DEBUG_MODE) {
    EXPECT_DEATH_IF_SUPPORTED(
        { LOG_DFATAL("dfatal ", IntStr(99)); }, "dfatal 99");
    LOG_DFATAL_IF(false, "dfatal if off ", 111);
    EXPECT_DEATH_IF_SUPPORTED(
        { LOG_DFATAL_IF(true, "dfatal if on ", 111); }, "dfatal if on 111");
  } else {
    LOG_DFATAL("dfatal ", IntStr(99));
    LOG_DFATAL_IF(false, "dfatal if off ", 111);
    LOG_DFATAL_IF(true, "dfatal if on ", 111);
  }
}

TEST(ChecksTest, Check) {
  CHECK(true);
  CHECK_EQ(11, 11);
  CHECK_NE(11, 22);
  CHECK_LE(11, 11);
  CHECK_LE(11, 22);
  CHECK_LT(11, 22);
  CHECK_GE(11, 11);
  CHECK_GE(22, 11);
  CHECK_GT(22, 11);

  DCHECK(true);
  DCHECK_EQ(11, 11);
  DCHECK_NE(11, 22);
  DCHECK_LE(11, 11);
  DCHECK_LE(11, 22);
  DCHECK_LT(11, 22);
  DCHECK_GE(11, 11);
  DCHECK_GE(22, 11);
  DCHECK_GT(22, 11);

  // A couple of failing cases:
  ABSL_ATTRIBUTE_UNUSED bool my_false = false;
  EXPECT_DEATH_IF_SUPPORTED({ CHECK(my_false); }, "Check failed: my_false");
  EXPECT_DEATH_IF_SUPPORTED({ CHECK_LE(22, 11); }, "Check failed: 22 <= 11");
  if (DEBUG_MODE) {
    EXPECT_DEATH_IF_SUPPORTED({ DCHECK(my_false); }, "Check failed: my_false");
    EXPECT_DEATH_IF_SUPPORTED({ DCHECK_LE(22, 11); }, "Check failed: 22 <= 11");
  } else {
    DCHECK(my_false);
    DCHECK_LE(22, 11);
  }
}

TEST(ChecksTest, CheckLog) {
  CHECK_LOG(true, "unused");
  CHECK_EQ_LOG(11, 11, "unused");
  CHECK_NE_LOG(11, 22, "unused");
  CHECK_LE_LOG(11, 11, "unused");
  CHECK_LT_LOG(11, 22, "unused");
  CHECK_GE_LOG(11, 11, "unused");
  CHECK_GT_LOG(22, 11, "unused");

  DCHECK_LOG(true, "unused");
  DCHECK_EQ_LOG(11, 11, "unused");
  DCHECK_NE_LOG(11, 22, "unused");
  DCHECK_LE_LOG(11, 11, "unused");
  DCHECK_LT_LOG(11, 22, "unused");
  DCHECK_GE_LOG(11, 11, "unused");
  DCHECK_GT_LOG(22, 11, "unused");

  // A couple of failing cases:
  ABSL_ATTRIBUTE_UNUSED bool my_false = false;
  EXPECT_DEATH_IF_SUPPORTED(
      { CHECK_LOG(my_false, ", llama"); }, "Check failed: my_false .+ llama");
  EXPECT_DEATH_IF_SUPPORTED(
      { CHECK_LE_LOG(22, 11, ", badger"); },
      "Check failed: 22 <= 11 .+ badger");
  if (DEBUG_MODE) {
    EXPECT_DEATH_IF_SUPPORTED(
        { DCHECK_LOG(my_false, ", fox"); }, "Check failed: my_false .+ fox");
    EXPECT_DEATH_IF_SUPPORTED(
        { DCHECK_LE_LOG(22, 11, ", pheasant"); },
        "Check failed: 22 <= 11 .+ pheasant");
  } else {
    DCHECK_LOG(my_false, "unused");
    DCHECK_LE_LOG(22, 11, "unused");
  }
}

// TODO(ksteuck): [test] Actually test the ASS_*() macros in async-signal-safe
// contexts.

TEST(ChecksTest, ASSLog) {
  ASS_LOG_ERROR("error ", IntStr(11));
  ASS_LOG_INFO("info ", IntStr(22));
  ASS_VLOG_INFO(10, "vlog off ", IntStr(33));
  ASS_VLOG_INFO(-10, "vlog on ", IntStr(33));
  ASS_LOG_INFO_IF(false, "info if off ", IntStr(44));
  ASS_LOG_INFO_IF(true, "info if on ", IntStr(44));

  EXPECT_DEATH_IF_SUPPORTED(
      { ASS_LOG_FATAL("fatal ", IntStr(55)); }, "fatal 55");
  if (DEBUG_MODE) {
    EXPECT_DEATH_IF_SUPPORTED(
        { ASS_LOG_DFATAL("dfatal ", IntStr(66)); }, "dfatal 66");
  } else {
    ASS_LOG_DFATAL("dfatal ", IntStr(66));
  }
}

TEST(ChecksTest, ASSCheck) {
  ASS_CHECK(true);
  ASS_DCHECK(true);

  ABSL_ATTRIBUTE_UNUSED bool my_false = false;
  EXPECT_DEATH_IF_SUPPORTED({ ASS_CHECK(my_false); }, "Check failed: my_false");
  if (DEBUG_MODE) {
    EXPECT_DEATH_IF_SUPPORTED(
        { ASS_DCHECK(my_false); }, "Check failed: my_false");
  } else {
    ASS_DCHECK(my_false);
  }
}

TEST(ChecksTest, CheckAndUse) {
  int v = CHECK_AND_USE(true, 11);
  CHECK_EQ(v, 11);
  v = DCHECK_AND_USE(true, 11);
  CHECK_EQ(v, 11);

  ABSL_ATTRIBUTE_UNUSED bool my_false = false;
  EXPECT_DEATH_IF_SUPPORTED(
      { v = CHECK_AND_USE(my_false, 33); }, "Check condition failed: my_false");
  if (DEBUG_MODE) {
    EXPECT_DEATH_IF_SUPPORTED(
        { v = DCHECK_AND_USE(my_false, 44); },
        "Check condition failed: my_false");
  } else {
    v = DCHECK_AND_USE(my_false, 44);
    CHECK_EQ(v, 44);
  }
}

#if !defined(SILIFUZZ_BUILD_FOR_NOLIBC)

absl::StatusOr<int> IntOrFunction(bool cond, bool plus_cond) {
  auto ok = absl::Status();
  RETURN_IF_NOT_OK(ok);
  RETURN_IF_NOT_OK_PLUS(ok, "never used");

  auto error = absl::Status(absl::StatusCode::kInternal, "error-one");
  if (cond) RETURN_IF_NOT_OK(error);

  error = absl::Status(absl::StatusCode::kInternal, "error-two");
  if (plus_cond) RETURN_IF_NOT_OK_PLUS(error, "extra-reason: ");

  return 42;
}

TEST(ChecksTest, Status) {
  auto ok = absl::Status();
  auto error = absl::Status(absl::StatusCode::kInternal, "My-error-event");

  CHECK_STATUS(ok);
  DCHECK_STATUS(ok);

  EXPECT_DEATH_IF_SUPPORTED({ CHECK_STATUS(error); }, "My-error-event");
  if (DEBUG_MODE) {
    EXPECT_DEATH_IF_SUPPORTED({ DCHECK_STATUS(error); }, "My-error-event");
  } else {
    DCHECK_STATUS(error);
  }

  // Test RETURN_IF_NOT_OK(_PLUS)():
  auto r = IntOrFunction(false, false);
  CHECK_EQ(r.value(), 42);

  r = IntOrFunction(true, false);
  CHECK(!r.ok());
  CHECK_EQ(r.status().message(), "error-one");

  r = IntOrFunction(false, true);
  CHECK(!r.ok());
  CHECK_EQ(r.status().message(), "extra-reason: error-two");
}

#endif  // !defined(SILIFUZZ_BUILD_FOR_NOLIBC)

}  // namespace
}  // namespace silifuzz

// ========================================================================= //

NOLIBC_TEST_MAIN({
  RUN_TEST(ChecksTest, Log);
  RUN_TEST(ChecksTest, Check);
  RUN_TEST(ChecksTest, CheckLog);
  RUN_TEST(ChecksTest, ASSLog);
  RUN_TEST(ChecksTest, ASSCheck);
  RUN_TEST(ChecksTest, CheckAndUse);
})
