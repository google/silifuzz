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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_ENUM_FLAG_TYPES_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_ENUM_FLAG_TYPES_H_

#include "./util/arch.h"
#include "./util/enum_flag.h"
#include "./util/platform.h"

// ClangTidy cannot see the declaration inside DECLARE_ENUM_FLAG being consumed
// by ABSL_FLAG. Hack around this by marking the header always keep.
// IWYU pragma: always_keep

namespace silifuzz {

// These are all the enum flags used by more than one command-line tool.
// Enum flag parsing is incompatible with nolibc, so we keep the flag parsers
// in a separate file. The main concern is ArchitectureId, since it pervades
// the codebase.

DECLARE_ENUM_FLAG(ArchitectureId);
DECLARE_ENUM_FLAG(PlatformId);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_ENUM_FLAG_TYPES_H_
