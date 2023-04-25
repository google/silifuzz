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

#include "./util/proto_util.h"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <string>

#include "google/protobuf/text_format.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./util/checks.h"

namespace silifuzz {

absl::Status ReadFromFile(absl::string_view filename,
                          ::google::protobuf::MessageLite* proto) {
  int fd = open(std::string(filename).c_str(), O_RDONLY);
  if (fd == -1) {
    return absl::PermissionDeniedError(
        absl::StrCat("Could not open file ", filename, " : ", strerror(errno)));
  }
  bool parsed = proto->ParseFromFileDescriptor(fd);
  bool closed = close(fd) == 0;
  if (!parsed) {
    return absl::InternalError(absl::StrCat("Could not parse proto from file ",
                                            filename, " into ",
                                            proto->GetTypeName()));
  }
  if (!closed) {
    return absl::InternalError(absl::StrCat("Could not close file ", filename,
                                            " : ", strerror(errno)));
  }
  return absl::OkStatus();
}

absl::Status WriteToFile(const ::google::protobuf::MessageLite& proto,
                         absl::string_view filename) {
  int fd = creat(std::string(filename).c_str(), S_IRUSR | S_IWUSR | S_IRGRP);
  if (fd == -1) {
    return absl::InternalError(
        absl::StrCat("Could not open file ", filename, " : ", strerror(errno)));
  }
  bool serialized = proto.SerializeToFileDescriptor(fd);
  bool closed = close(fd) == 0;
  if (!serialized) {
    return absl::InternalError(
        absl::StrCat("Could not serialize proto to file ", filename));
  }
  if (!closed) {
    return absl::InternalError(absl::StrCat("Could not close file ", filename,
                                            " : ", strerror(errno)));
  }
  return absl::OkStatus();
}

absl::StatusOr<std::string> ReadFile(absl::string_view filename) {
  int fd = open(std::string(filename).c_str(), O_RDONLY);
  if (fd == -1) {
    return absl::PermissionDeniedError(
        absl::StrCat("Could not open file ", filename, " : ", strerror(errno)));
  }
  char buf[1024];
  std::string result;
  ssize_t n = 0;
  int saved_errno = 0;
  do {
    do {
      n = read(fd, buf, sizeof(buf));
    } while (n == -1 && errno == EINTR);
    if (n == -1) {
      saved_errno = errno;
      break;
    }
    result.append(buf, n);
  } while (n > 0);
  if (close(fd) != 0) {
    return absl::InternalError(absl::StrCat("Could not close file ", filename,
                                            " : ", strerror(errno)));
  }
  if (saved_errno != 0) {
    return absl::InternalError(absl::StrCat("Could not read file ", filename,
                                            " : ", strerror(saved_errno)));
  }
  return result;
}

absl::Status ReadFromTextFile(absl::string_view filename,
                              ::google::protobuf::Message* proto) {
  ASSIGN_OR_RETURN_IF_NOT_OK(auto data, ReadFile(filename));
  if (!google::protobuf::TextFormat::ParseFromString(data, proto)) {
    return absl::InternalError(absl::StrCat("Failed to parse ", filename,
                                            " into ", proto->GetTypeName()));
  }
  return absl::OkStatus();
}

}  // namespace silifuzz
