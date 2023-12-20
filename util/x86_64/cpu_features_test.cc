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

#include "./util/cpu_features.h"

#include <cstddef>
#include <fstream>
#include <set>
#include <string>

#include "gtest/gtest.h"
#include "absl/strings/match.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"

namespace silifuzz {
namespace {

TEST(CPUFeatures, CanCheckAllFeatures) {
  for (X86CPUFeatures f = X86CPUFeatures::kBegin; f < X86CPUFeatures::kEnd;
       f = X86CPUFeatures{static_cast<int>(f) + 1}) {
    // We should be able to check all features.
    const bool result1 = HasX86CPUFeature(f);
    const bool result2 = HasX86CPUFeature(f);
    // Features should be constant.
    EXPECT_EQ(result1, result2);
  }
}

// Checks if our results agree with information in /proc/cpuinfo.
TEST(CPUFeatures, VerifyAgainstCPUInfo) {
  // Extract flags in /proc/cpuinfo
  std::ifstream ifs("/proc/cpuinfo");
  std::string line;
  const absl::string_view kPrefix = "flags";
  std::set<std::string> flags;
  while (std::getline(ifs, line)) {
    absl::string_view sv(line);
    if (absl::StartsWith(sv, kPrefix)) {
      // skip until ':'
      size_t pos = sv.find(':');
      ASSERT_NE(pos, absl::string_view::npos);
      sv.remove_prefix(pos + 1);
      flags = absl::StrSplit(sv, ' ');
      break;
    }
  }
  ASSERT_FALSE(flags.empty());

  auto verify_features = [&flags](X86CPUFeatures feature,
                                  const std::string& flag) {
    EXPECT_EQ(HasX86CPUFeature(feature), flags.find(flag) != flags.end());
  };

  verify_features(X86CPUFeatures::kAMX_TILE, "amx_tile");
  verify_features(X86CPUFeatures::kAVX, "avx");
  verify_features(X86CPUFeatures::kAVX512BW, "avx512bw");
  verify_features(X86CPUFeatures::kAVX512F, "avx512f");
  verify_features(X86CPUFeatures::kSSE, "sse");
  verify_features(X86CPUFeatures::kSSE, "sse4_2");
  verify_features(X86CPUFeatures::kXSAVE, "xsave");
}

}  // namespace
}  // namespace silifuzz
