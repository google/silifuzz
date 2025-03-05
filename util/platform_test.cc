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

#include "./util/platform.h"

#include <cstdint>
#include <string>

#include "gtest/gtest.h"
#include "absl/container/flat_hash_map.h"
#include "absl/strings/ascii.h"
#include "absl/strings/match.h"
#include "absl/strings/str_replace.h"
#include "./proto/snapshot.pb.h"
#include "./util/arch.h"
#include "./util/itoa.h"

namespace silifuzz {

namespace {

// A quick test to catch when new platforms get added to prod.
// If this test becomes flaky then a new entry should be added to the PlatformId
// enum.
TEST(PlatformTest, CurrentPlatformId) {
  ASSERT_NE(CurrentPlatformId(), PlatformId::kUndefined)
      << "New platform was added to the fleet. Look at the error log and update"
      << " PlatformId enum accordingly";

  ASSERT_EQ(PlatformArchitecture(CurrentPlatformId()), Host::architecture_id);
}

TEST(PlatformTest, NoGaps) {
  ASSERT_STREQ(EnumStr(PlatformId::kNonExistent), "NON-EXISTENT-PLATFORM");
}

TEST(PlatformTest, PlatformArchitecture) {
  for (int i = proto::PlatformId_MIN; i < proto::PlatformId_MAX; ++i) {
    if (proto::PlatformId_IsValid(i)) {
      const std::string& enum_name = proto::PlatformId_Name(i);
      ArchitectureId arch = PlatformArchitecture(static_cast<PlatformId>(i));
      if (absl::StrContains(enum_name, "RESERVED") ||
          static_cast<PlatformId>(i) == PlatformId::kUndefined) {
        EXPECT_EQ(arch, ArchitectureId::kUndefined)
            << "Platform " << enum_name
            << " unexpectedly mapped to a defined architecture";
      } else {
        EXPECT_TRUE(arch == ArchitectureId::kX86_64 ||
                    arch == ArchitectureId::kAArch64)
            << "Platform " << enum_name
            << " doesn't map to a valid architecture";
      }
    }
  }
}

TEST(PlatformTest, PlatformNameMatchesEnum) {
  // `kAny` and `kNonExistent` are meta-values that won't be persisted in the
  // proto representation.
  EXPECT_EQ(proto::PlatformId_MAX, static_cast<int>(kMaxPlatformId) - 2)
      << "snapshot.proto is not up to date with the latest changes in platform "
         "ids.";
  for (int i = proto::PlatformId_MIN; i < proto::PlatformId_MAX; ++i) {
    if (proto::PlatformId_IsValid(i)) {
      std::string internal_name = absl::StrReplaceAll(
          absl::AsciiStrToUpper(EnumStr(static_cast<PlatformId>(i))),
          {{"-", "_"}});
      EXPECT_EQ(internal_name, proto::PlatformId_Name(i));
    }
  }
}

TEST(PlatformTest, EnumNameMap) {
  EXPECT_EQ(EnumNameMap<PlatformId>[static_cast<int>(kMaxPlatformId)],
            "NON-EXISTENT-PLATFORM")
      << "EnumNameMap is not up to date with the latest changes in platform "
         "ids.";
}

struct CpuId {
  uint32_t family;
  uint32_t model;
  uint32_t stepping;
};

// Note: these maps only provide 1 example cpu id of each platform as a simple
// check. This test primarily guards against us forgetting to add a new platform
// mapping to this file and does not cover all cases.
const absl::flat_hash_map<PlatformId, CpuId> kAmdPlatformToCpuId = {
    {PlatformId::kAmdRome, {23, 48, 0}},
    {PlatformId::kAmdMilan, {25, 10, 0}},
    {PlatformId::kAmdGenoa, {25, 16, 0}},
    {PlatformId::kAmdRyzenV3000, {25, 64, 0}},
    {PlatformId::kAmdSiena, {25, 160, 0}},
    {PlatformId::kAmdTurin, {26, 2, 0}},
};
const absl::flat_hash_map<PlatformId, CpuId> kIntelPlatformToCpuId = {
    {PlatformId::kIntelHaswell, {6, 60, 0}},
    {PlatformId::kIntelBroadwell, {6, 61, 0}},
    {PlatformId::kIntelIvybridge, {6, 62, 0}},
    {PlatformId::kIntelSkylake, {6, 85, 1}},
    {PlatformId::kIntelCascadelake, {6, 85, 5}},
    {PlatformId::kIntelIcelake, {6, 106, 0}},
    {PlatformId::kIntelCoffeelake, {6, 142, 0}},
    {PlatformId::kIntelSapphireRapids, {6, 143, 0}},
    {PlatformId::kIntelAlderlake, {6, 151, 0}},
    {PlatformId::kIntelGraniteRapids, {6, 173, 0}},
    {PlatformId::kIntelEmeraldRapids, {6, 207, 0}},
};

TEST(PlatformUtilsX86, AmdPlatformIdFromCpuId) {
  for (const auto& [platform, cpu_id] : kAmdPlatformToCpuId) {
    EXPECT_EQ(internal::AmdPlatformIdFromCpuId(cpu_id.family, cpu_id.model,
                                               cpu_id.stepping),
              platform);
  }
}

TEST(PlatformUtilsX86, IntelPlatformIdFromCpuId) {
  for (const auto& [platform, cpu_id] : kIntelPlatformToCpuId) {
    EXPECT_EQ(internal::IntelPlatformIdFromCpuId(cpu_id.family, cpu_id.model,
                                                 cpu_id.stepping),
              platform);
  }
}

TEST(PlatformUtilsX86, AllX86PlatformsAreMapped) {
  for (int i = 0; i <= static_cast<int>(kMaxPlatformId); ++i) {
    PlatformId platform = static_cast<PlatformId>(i);
    if (PlatformArchitecture(platform) == ArchitectureId::kX86_64) {
      EXPECT_TRUE(kAmdPlatformToCpuId.contains(platform) ||
                  kIntelPlatformToCpuId.contains(platform))
          << "X86-64 platform " << EnumStr(platform)
          << " is not mapped to a CPU ID in silifuzz/util/platform.cc, or a"
             "test case is not added.";
    }
  }
}

struct ArmMainId {
  uint32_t implementer;
  uint32_t part_number;
  PlatformId mapped_platform;  // Some concrete platforms are mapped to abstract
                               // platforms (ARM Neoverse v2, v3).
};

const absl::flat_hash_map<PlatformId, ArmMainId> kArmPlatformToCpuId = {
    {PlatformId::kArmNeoverseN1, {0x41, 0xd0c, PlatformId::kArmNeoverseN1}},
    {PlatformId::kArmNeoverseV2, {0x41, 0xd4f, PlatformId::kArmNeoverseV2}},
    {PlatformId::kArmNeoverseN3, {0x41, 0xd8e, PlatformId::kArmNeoverseN3}},
    {PlatformId::kAmpereOne, {0xc0, 0xac3, PlatformId::kAmpereOne}},
};

TEST(PlatformUtilsAarch, ArmPlatformIdFromMainId) {
  for (const auto& [platform, main_id] : kArmPlatformToCpuId) {
    PlatformId actual_mapped_platform = internal::ArmPlatformIdFromMainId(
        main_id.implementer, main_id.part_number);
    EXPECT_EQ(actual_mapped_platform, main_id.mapped_platform)
        << EnumStr(platform) << " is unexpectedly mapped to "
        << EnumStr(actual_mapped_platform) << " instead of "
        << EnumStr(main_id.mapped_platform);
  }
}

TEST(PlatformUtilsAarch, AllAArch64PlatformsAreMapped) {
  for (int i = 0; i <= static_cast<int>(kMaxPlatformId); ++i) {
    PlatformId platform = static_cast<PlatformId>(i);
    if (PlatformArchitecture(platform) == ArchitectureId::kAArch64) {
      EXPECT_TRUE(kArmPlatformToCpuId.contains(platform))
          << "AArch64 platform " << EnumStr(platform)
          << " is not mapped to a CPU ID in silifuzz/util/platform.cc, or a "
             "test case is not added.";
    }
  }
}

}  // namespace
}  // namespace silifuzz
