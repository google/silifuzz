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

#if defined(__x86_64__)
#include "./util/x86_cpuid.h"

#include <stdint.h>

#include "./util/checks.h"
#include "./util/nolibc_gunit.h"

// ========================================================================= //

namespace silifuzz {
namespace {

TEST(X86CPUID, BasicTest) {
  X86CPUIDResult result;

  // Get highest extended function parameter.  We expect this to be higher
  // than 0x80000000 on all platforms we use.
  X86CPUID(0x80000000, &result);
  const uint32_t highest_function_parameter = result.eax;
  CHECK_GT(highest_function_parameter, 0x80000000U);

  // Get vendor string
  X86CPUVendorID vendor_id_string;
  LOG_INFO("vendor ID: ", vendor_id_string.get());
  CHECK(vendor_id_string.IsAMD() || vendor_id_string.IsIntel());
}

}  // namespace
}  // namespace silifuzz

// ========================================================================= //

NOLIBC_TEST_MAIN({ RUN_TEST(X86CPUID, BasicTest); })

#endif  // defined(__x86_64__)
