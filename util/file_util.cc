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

#include "./util/file_util.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "absl/strings/string_view.h"
#include "./util/byte_io.h"
#include "./util/checks.h"
#include "./util/itoa.h"

namespace silifuzz {

bool WriteToFileDescriptor(int fd, absl::string_view contents) {
  return Write(fd, contents.data(), contents.size()) == contents.size();
}

bool SetContents(absl::string_view file_name, absl::string_view contents) {
  int fd = open(std::string(file_name).c_str(), O_WRONLY | O_CREAT | O_TRUNC,
                S_IRUSR | S_IWUSR);
  if (fd == -1) {
    LOG_ERROR("open: ", ErrnoStr(errno));
    return false;
  }
  bool write_status = WriteToFileDescriptor(fd, contents);
  if (close(fd) != 0) {
    LOG_ERROR("close: ", ErrnoStr(errno));
    return false;
  }
  return write_status;
}

}  // namespace silifuzz
