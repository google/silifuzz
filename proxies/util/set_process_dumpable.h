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

#ifndef THIRD_PARTY_SILIFUZZ_PROXIES_UTIL_SET_PROCESS_DUMPABLE_H_
#define THIRD_PARTY_SILIFUZZ_PROXIES_UTIL_SET_PROCESS_DUMPABLE_H_

#include "absl/status/status.h"

namespace silifuzz::proxies {

// Proxies are linked with the centipede runner library, which uses
// PR_SET_DUMPABLE to disable core dumps. Unfortunately that also makes most of
// /proc/self to be owned by root and generally inaccessible. That breaks
// passing mem file paths /proc/XX/fd/YY.
//
// For proxies that need to use mem files in /proc, this function sets
// PR_SET_DUMPALBE to 1 but limits core dump size to be 0 instead. It is better
// to generate empty core files than to have snap maker not working. In theory,
// this can still be a problem if for some reason, the proxy crashes extremely
// frequently such that too many core files can pose a problem. Empirically this
// has not be observed in a limited-time test run. Core dumping is rare.
absl::Status SetProcessDumpable();

}  // namespace silifuzz::proxies

#endif  // THIRD_PARTY_SILIFUZZ_PROXIES_UTIL_SET_PROCESS_DUMPABLE_H_
