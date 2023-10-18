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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_ENUM_FLAG_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_ENUM_FLAG_H_

#include <string>
#include <type_traits>  // for std::enable_if_t, std::is_enum

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./util/checks.h"
#include "./util/itoa.h"

namespace silifuzz {

// Parses EnumT value from string.
// Relies on the same EnumNameMap<> as EnumStr() from ./itoa.h for the parsing.
template <typename EnumT, std::enable_if_t<std::is_enum<EnumT>::value, int> = 0>
ABSL_MUST_USE_RESULT absl::StatusOr<EnumT> ParseEnum(absl::string_view value) {
  // Not using std::size() here as we want to support 0-sized arrays too.
  int num_values = sizeof(EnumNameMap<EnumT>) / sizeof(const char*);
  for (int i = 0; i < num_values; ++i) {
    if (EnumNameMap<EnumT>[i] != nullptr && value == EnumNameMap<EnumT>[i]) {
      return static_cast<EnumT>(i);
    }
  }
  std::string msg = absl::StrCat("No match for \"", value,
                                 "\" in EnumNameMap<EnumT>\nWant one of: ");
  constexpr int kMaxValuesInStatus = 10;
  for (int i = 0; i < num_values && i < kMaxValuesInStatus; ++i) {
    if (EnumNameMap<EnumT>[i] != nullptr) {
      absl::StrAppend(&msg, EnumNameMap<EnumT>[i], ", ");
    }
  }
  if (num_values > kMaxValuesInStatus) {
    absl::StrAppend(&msg, num_values - kMaxValuesInStatus, " values omitted");
  }

  return absl::Status(absl::StatusCode::kInvalidArgument, msg);
}

// Or-die variant of ParseEnum().
template <typename EnumT, std::enable_if_t<std::is_enum<EnumT>::value, int> = 0>
EnumT ParseEnumOrDie(absl::string_view value) {
  auto v_or = ParseEnum<EnumT>(value);
  CHECK_STATUS(v_or.status());
  return v_or.value();
}

// ========================================================================= //

// Helpers for defining enum absl flags that rely on ParseEnum() above.
//
// After doing
//   DEFINE_ENUM_FLAG(EnumT);
// in the namespace of EnumT one can do
//   ABSL_FLAG(EnumT, foo, bar, "Baz....");
// while affter doing
//   DECLARE_ENUM_FLAG(EnumT);
// in the namespace of EnumT one can do
//   ABSL_DECLARE_FLAG(EnumT, foo);
#define DECLARE_ENUM_FLAG(EnumT)                                            \
  bool AbslParseFlag(absl::string_view text, EnumT* x, std::string* error); \
  std::string AbslUnparseFlag(EnumT x);
#define DEFINE_ENUM_FLAG(EnumT)                                              \
  bool AbslParseFlag(absl::string_view text, EnumT* x, std::string* error) { \
    auto v_or = ::silifuzz::ParseEnum<EnumT>(text);                          \
    if (v_or.ok()) {                                                         \
      *x = v_or.value();                                                     \
      return true;                                                           \
    } else {                                                                 \
      *error = v_or.status().message();                                      \
      return false;                                                          \
    }                                                                        \
  }                                                                          \
  std::string AbslUnparseFlag(EnumT x) { return ::silifuzz::EnumStr(x); }

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_ENUM_FLAG_H_
