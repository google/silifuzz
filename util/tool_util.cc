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

#include "./util/tool_util.h"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "absl/flags/parse.h"
#include "absl/flags/usage.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "./util/checks.h"
#include "./util/line_printer.h"

namespace silifuzz {

const char* ConsumeArg(std::vector<char*>& args) {
  DCHECK_GE(args.size(), 1);
  auto arg = args[0];
  args.erase(args.begin());
  return arg;
}

bool ExtraArgs(const std::vector<char*>& args) {
  if (!args.empty()) {
    LOG_ERROR("Unexpected command argument(s).");
    return true;
  }
  return false;
}

int SubcommandMain(int argc, char** argv, const char* tool_name,
                   absl::Span<const Subcommand> subcommands) {
  LinePrinter out(LinePrinter::StdOutPrinter);
  LinePrinter err(LinePrinter::StdErrPrinter);

  // Generate usage string
  std::vector<const char*> command_names;
  for (const Subcommand& subcommand : subcommands) {
    command_names.push_back(subcommand.name);
  }
  absl::SetProgramUsageMessage(absl::StrCat(
      tool_name, " {", absl::StrJoin(command_names, ","), "} <args>"));

  std::vector<char*> positional_args = absl::ParseCommandLine(argc, argv);

  // Erase the executable path.
  CHECK(!positional_args.empty());
  ConsumeArg(positional_args);

  // Parse the subcommand name.
  if (positional_args.empty()) {
    err.Line("Must specify subcommand.");
    err.Line("Usage: ", absl::ProgramUsageMessage());
    return EXIT_FAILURE;
  }
  const char* name = ConsumeArg(positional_args);

  // Call the subcommand.
  for (const Subcommand& subcommand : subcommands) {
    if (strcmp(name, subcommand.name) == 0) {
      absl::StatusOr<int> status_or =
          subcommand.func(positional_args, out, err);
      if (status_or.ok()) {
        return status_or.value();
      } else {
        err.Line(status_or.status().message());
        return EXIT_FAILURE;
      }
    }
  }

  // Or fail if the subcommand is not found.
  err.Line("Unknown subcommand: ", name);
  err.Line("Usage: ", absl::ProgramUsageMessage());
  return EXIT_FAILURE;
}

absl::StatusOr<std::string> GetFileContents(absl::string_view file_name) {
  int fd = open(file_name.data(), O_RDONLY);
  if (fd == -1) {
    return absl::PermissionDeniedError(
        absl::StrCat("Could not open file ", file_name, ": ", strerror(errno)));
  }
  off_t size = lseek(fd, 0, SEEK_END);
  if (size == -1) {
    close(fd);
    return absl::UnknownError(
        absl::StrCat("Could not seek ", file_name, ": ", strerror(errno)));
  }
  if (lseek(fd, 0, SEEK_SET) != 0) {
    close(fd);
    return absl::UnknownError(
        absl::StrCat("Could not seek ", file_name, ": ", strerror(errno)));
  }

  std::string buffer(size, 0);

  char* data = buffer.data();
  size_t data_read = 0;
  while (data_read < size) {
    int result = read(fd, data, size - data_read);
    if (result == 0) {
      buffer.resize(data_read);
      break;
    }
    if (result == -1) {
      close(fd);
      return absl::UnknownError(absl::StrCat("Could only read ", data_read,
                                             " bytes from ", file_name, ": ",
                                             strerror(errno)));
    }
    data += result;
    data_read += result;
  }
  close(fd);
  return buffer;
}

absl::StatusOr<std::string> GetSysfsFileContents(absl::string_view file_name) {
  ASSIGN_OR_RETURN_IF_NOT_OK(std::string contents, GetFileContents(file_name));
  // Strip terminating null from end of buffer.
  contents.resize(contents.size() - 1);
  return contents;
}

}  // namespace silifuzz
