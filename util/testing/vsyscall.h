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
#ifndef THIRD_PARTY_SILIFUZZ_UTIL_TESTING_VSYSCALL_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_TESTING_VSYSCALL_H_

#include "absl/status/statusor.h"
namespace silifuzz {

// Returns a boolean indicating whether legacy vsyscall region is present
// and readable on the host or a status if an error happened. Depending on
// kernel config, the vsyscall region can be readable, executable-only or
// unmapped.
absl::StatusOr<bool> VSyscallRegionReadable();

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_TESTING_VSYSCALL_H_
