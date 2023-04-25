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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_PROTO_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_PROTO_UTIL_H_

// This library defines a few simple utils for protos.

#include <string>

#include "google/protobuf/message_lite.h"
#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

// Quick proto-parsing helper to complain about semantically-required optionals.
#define PROTO_MUST_HAVE_FIELD(proto, field_name)        \
  {                                                     \
    if (!(proto).has_##field_name()) {                  \
      return absl::InvalidArgumentError(                \
          absl::StrCat("Missing field: " #field_name)); \
    }                                                   \
  }

// Quick proto-parsing helper to complain about not semantically-required
// optionals.
#define PROTO_MUST_NOT_HAVE_FIELD(proto, field_name)       \
  {                                                        \
    if ((proto).has_##field_name()) {                      \
      return absl::InvalidArgumentError(                   \
          absl::StrCat("Unexpected field: " #field_name)); \
    }                                                      \
  }

namespace silifuzz {

// Reads *proto from `filename`.
absl::Status ReadFromFile(absl::string_view filename,
                          ::google::protobuf::MessageLite* proto) ABSL_MUST_USE_RESULT;

// Writes `proto` to `filename`.
absl::Status WriteToFile(const ::google::protobuf::MessageLite& proto,
                         absl::string_view filename) ABSL_MUST_USE_RESULT;

// Reads the contents of the file specified by `filename` and returns the
// contents or status on any error.
absl::StatusOr<std::string> ReadFile(absl::string_view filename);

// Reads *proto from text-formatted file.
absl::Status ReadFromTextFile(absl::string_view filename,
                              ::google::protobuf::Message* proto) ABSL_MUST_USE_RESULT;

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_PROTO_UTIL_H_
