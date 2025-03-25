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

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "google/protobuf/message_lite.h"

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

}  // namespace silifuzz
