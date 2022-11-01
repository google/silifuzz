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

#include "./util/enum_flag.h"

namespace silifuzz {

template <>
ABSL_CONST_INIT const char* EnumNameMap<PlatformId>[ToInt(kMaxPlatformId) + 1] =
    {
        "UNDEFINED-PLATFORM", "intel-skylake",
        "intel-haswell",      "intel-broadwell",
        "intel-ivybridge",    "intel-cascadelake",
        "amd-rome",           "intel-icelake",
        "amd-milan",          "intel-sapphirerapids",
        "amd-genoa",          "intel-coffeelake",
        "intel-alderlake",    "arm-neoverse-n1",
        "ANY-PLATFORM",       "NON-EXISTENT-PLATFORM",
};

DEFINE_ENUM_FLAG(PlatformId);

// An arbitrary name, only used internally.
ABSL_CONST_INIT const char* kShortPlatformNames[ToInt(kMaxPlatformId) + 1] = {
    "UNDEF",   "skylk",  "haswl", "broadwl",  "ivybrdg", "cascdlk",
    "rome",    "icelk",  "milan", "sapprpds", "genoa",   "coffeelk",
    "alderlk", "neovn1", "ANY",   "NEXST",
};

const char* ShortPlatformName(PlatformId platform) {
  return kShortPlatformNames[ToInt(platform)];
}

}  // namespace silifuzz
