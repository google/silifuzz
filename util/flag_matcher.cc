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

#include "./util/flag_matcher.h"

#include <cstring>

#include "./util/checks.h"

namespace silifuzz {

bool CommandLineFlagMatcher::Match(const char* flag,
                                   ArgumentKind argument_kind) {
  if (optind_ >= argc_) {
    return false;
  }

  // Check for "--<flag>" prefix.
  const char* option = argv_[optind_];
  size_t flag_len = strlen(flag);
  if (option[0] != '-' || option[1] != '-' ||
      strncmp(option + 2, flag, flag_len) != 0) {
    return false;
  }

  // Complete match by checking the rest of argument after "--<flag>" prefix.
  const char* optarg = nullptr;
  int optind_delta = 1;
  const char* option_tail = option + flag_len + 2;
  const bool option_tail_empty = *option_tail == '\0';
  if (!option_tail_empty && *option_tail != '=') {
    return false;
  }

  // Check optional flag argument according to argument kind.
  if (argument_kind == kRequiredArgument) {
    if (option_tail_empty) {
      // Argument is next command line argument.
      if (optind_ + 1 >= argc_) {
        LOG_ERROR("Missing argument for flag --", flag);
        return false;
      } else {
        optarg = argv_[optind_ + 1];
        optind_delta = 2;
      }
    } else {
      // argument is what follows '='.
      optarg = option_tail + 1;
    }
  }

  // Update state if there is a match.
  optind_ += optind_delta;
  optarg_ = optarg;
  return true;
}

}  // namespace silifuzz
