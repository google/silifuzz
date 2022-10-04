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

#ifndef THIRD_PARTY_SILIFUZZ_PROXIES_UNICORN_X86_64_H_
#define THIRD_PARTY_SILIFUZZ_PROXIES_UNICORN_X86_64_H_

#include <cstddef>
#include <cstdint>

#include "absl/status/statusor.h"
#include "./util/checks.h"
#include "third_party/unicorn/unicorn.h"

#define UNICORN_CHECK(...)                                       \
  do {                                                           \
    uc_err __uc_check_err = __VA_ARGS__;                         \
    if ((__uc_check_err != UC_ERR_OK)) {                         \
      LOG_FATAL(#__VA_ARGS__ " failed %u: %s\n", __uc_check_err, \
                uc_strerror(__uc_check_err));                    \
    }                                                            \
  } while (0);

#define UNICORN_RETURN_IF_NOT_OK(...)    \
  do {                                   \
    uc_err __uc_check_err = __VA_ARGS__; \
    if ((__uc_check_err != UC_ERR_OK)) { \
      return __uc_check_err;             \
    }                                    \
  } while (0);

namespace silifuzz {

// Does uc_open(uc) on scope entry, uc_close(*uc) on scope exit.
struct ScopedUC {
  explicit ScopedUC(uc_arch arch, uc_mode mode, uc_engine **uc) : uc_(uc) {
    UNICORN_CHECK(uc_open(arch, mode, uc_));
  }
  ~ScopedUC() { UNICORN_CHECK(uc_close(*uc_)); }
  uc_engine **uc_;
};

absl::StatusOr<uc_err> RunInstructions(absl::string_view insns);

};  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_PROXIES_UNICORN_X86_64_H_
