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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_PATH_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_PATH_UTIL_H_

#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

namespace silifuzz {

// Creates a unique temporary file with the given prefix and an optional
// suffix. See man mkstemps for details.
// The file is guaranteed to exist if this function returns a value.
// RETURNS file name or status if there was an error.
absl::StatusOr<std::string> CreateTempFile(absl::string_view prefix,
                                           absl::string_view suffix = "");

// Returns the part of the path after the final "/".  If there is no
// "/" in the path, the result is the same as the input.
absl::string_view Basename(absl::string_view path);

// Returns the part of the path before the final "/", EXCEPT:
// * If there is a single leading "/" in the path, the result will be the
//   leading "/".
// * If there is no "/" in the path, the result is the empty prefix of the
//   input string.
absl::string_view Dirname(absl::string_view path);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_PATH_UTIL_H_
