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

#include "./orchestrator/env.h"

#include <unistd.h>

#include <cerrno>
#include <string>

#include "absl/strings/string_view.h"
#include "./util/checks.h"
#include "./util/itoa.h"

namespace silifuzz {

absl::string_view Hostname() {
  static const std::string* hostname = [] {
    std::string* hostname = new std::string(256, '\0');
    if (gethostname(hostname->data(), hostname->size()) != 0) {
      LOG_FATAL("gethostname() failed with ", ErrnoStr(errno));
    }
    DCHECK_NE(hostname->find('\0'), hostname->npos);
    return hostname;
  }();
  return hostname->c_str();
}

absl::string_view ShortHostname() {
  absl::string_view hostname = Hostname();
  auto dot_pos = hostname.find('.');
  if (dot_pos != hostname.npos) {
    return absl::ClippedSubstr(hostname, 0, dot_pos);
  }
  return hostname;
}

}  // namespace silifuzz
