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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_VLOG_IS_ON_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_VLOG_IS_ON_H_

#if !defined(VLOG_IS_ON)

#define VLOG_IS_ON(level) (level <= 0)

#else
#error "Only include this header when VLOG isn't available"
#endif

// Also provide DEBUG_MODE
#ifndef NDEBUG
const bool DEBUG_MODE = true;
#else   // defined(NDEBUG)
const bool DEBUG_MODE = false;
#endif  // defined(NDEBUG)

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_VLOG_IS_ON_H_
