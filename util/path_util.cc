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

#include "./util/path_util.h"

#include <stdlib.h>  // for getenv()

#include <cerrno>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./util/itoa.h"

namespace silifuzz {

namespace {
std::string TempDir() {
  const char* google_tmpdir = getenv("TEST_TMPDIR");
  if (google_tmpdir != nullptr) {
    return google_tmpdir;
  }
  const char* tmpdir = getenv("TMPDIR");
  return tmpdir ? tmpdir : "/tmp";
}

std::pair<absl::string_view, absl::string_view> SplitPath(
    absl::string_view path) {
  size_t pos = path.find_last_of('/');

  // Handle the case with no '/' in 'path'.
  if (pos == absl::string_view::npos)
    return std::make_pair(path.substr(0, 0), path);

  // Handle the case with a single leading '/' in 'path'.
  if (pos == 0)
    return std::make_pair(path.substr(0, 1), absl::ClippedSubstr(path, 1));

  return std::make_pair(path.substr(0, pos),
                        absl::ClippedSubstr(path, pos + 1));
}

}  // namespace

absl::StatusOr<std::string> CreateTempFile(absl::string_view prefix,
                                           absl::string_view suffix) {
  int fd = -1;
  std::string template_str;
  do {
    template_str = absl::StrCat(TempDir(), "/", prefix, "-XXXXXX", suffix);
    fd = mkstemps(template_str.data(), suffix.size());
  } while (fd == -1 && errno == EEXIST);
  if (fd == -1) {
    return absl::InternalError(
        absl::StrCat("mkstemps(", template_str, "): ", ErrnoStr(errno)));
  }
  close(fd);
  return template_str;
}

absl::string_view Dirname(absl::string_view path) {
  return SplitPath(path).first;
}

absl::string_view Basename(absl::string_view path) {
  return SplitPath(path).second;
}

}  // namespace silifuzz
