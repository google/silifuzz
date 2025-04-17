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

#include "./util/checks.h"

#include <cstdint>
#include <limits>

namespace silifuzz {

namespace checks_internal {

static const char kHexCharMap[] = "0123456789abcdef";

char* IntStr(int64_t num, char (&buf)[kIntStrBufferSize]) {
  // digits10 is the floor, we want ceil. +1 is a conservative approximation.
  constexpr auto max_digits = std::numeric_limits<decltype(num)>::digits10 + 1;
  static_assert(sizeof(buf) >= max_digits + 2, "Increase size of buf");
  char* ptr = buf + sizeof(buf);
  *--ptr = '\0';
  bool is_neg = num < 0;
  // We do not do num = -num as it does not work for the abs-largest negative
  // int64.
  do {
    *--ptr = kHexCharMap[is_neg ? -(num % 10) : (num % 10)];
    num /= 10;
  } while (num != 0);
  if (is_neg) {
    *--ptr = '-';
  }
  return ptr;
}

}  // namespace checks_internal

}  // namespace silifuzz

#if !defined(SILIFUZZ_BUILD_FOR_NOLIBC)

#include "absl/base/internal/raw_logging.h"

namespace silifuzz {
namespace checks_internal {

// When built with abseil logging libs we forward ASS_*() macros to
// raw_logging.h to be more consistent with other abseil libs.
// (In that case LogImpl() is only called from the ASS_*() macros.)
// Unfortunately we can't use public ABSL_RAW_LOG() interface:
// We need a function to provide default values for missing message[2345] args
// of ASS_LOG_INFO() and such, by which time we'd lose original file/line info
// if we called ABSL_RAW_LOG() in that function, so we peek into the impl
// of ABSL_RAW_LOG() a little.
void LogImpl(LogSeverity severity, const char* file, unsigned int line,
             const char* message1, IsMesssageChopped is_chopped,
             const char* message2, const char* message3, const char* message4,
             const char* message5) {
  ASS_DCHECK(is_chopped == kNotChopped);  // ASS_*() macros do not do this.
  absl::raw_log_internal::RawLog(static_cast<absl::LogSeverity>(severity), file,
                                 line, "%s%s%s%s%s", message1, message2,
                                 message3, message4, message5);
}

}  // namespace checks_internal

void SetVLogLevel(int vlog_level) {
  // No-op. vlog_level is controlled by the corresponding flags defined in
  // vlog_is_on.cc
}

}  // namespace silifuzz

#else  // defined(SILIFUZZ_BUILD_FOR_NOLIBC)

#include <string.h>  // for strlen()
#include <unistd.h>  // for STDERR_FILENO

#include <cerrno>  // for errno and EINTR.

namespace silifuzz {

void SetVLogLevel(int vlog_level) { checks_internal::vlog_level = vlog_level; }

namespace checks_internal {

// Default value is the same as in absl/log/vlog_is_on.cc for the --v flag.
ABSL_CONST_INIT int vlog_level = 0;

// Writes `str` to stderr.
// Is async-signal-safe.
static void WriteToStdErr(const char* str) {
  size_t len = strlen(str);
  ssize_t rc;
  do {
    rc = write(STDERR_FILENO, str, len);
  } while (rc < 0 && errno == EINTR);
}

void LogImpl(LogSeverity severity, const char* file, unsigned int line,
             const char* message1, IsMesssageChopped is_chopped,
             const char* message2, const char* message3, const char* message4,
             const char* message5) {
  WriteToStdErr(severity == kInfo ? "I" : (severity == kError ? "E" : "F"));
  // TODO(ksteuck): [as-needed] Fill in this reasonably to make the log format
  // even more similar to abseil/log/log.h. Borrow from raw_logging.cc.
  WriteToStdErr("<DATE> <PID> ");
  WriteToStdErr(file);
  WriteToStdErr(":");
  char int_str_buf[kIntStrBufferSize];
  WriteToStdErr(IntStr(line, int_str_buf));
  WriteToStdErr("] ");
  WriteToStdErr(message1);
  if (message2[0] != '\0') WriteToStdErr(message2);
  if (message3[0] != '\0') WriteToStdErr(message3);
  if (message4[0] != '\0') WriteToStdErr(message4);
  if (message5[0] != '\0') WriteToStdErr(message5);
  if (is_chopped == kChopped) {
    WriteToStdErr(" ... -- details were dropped");
  }
  WriteToStdErr("\n");

  if (severity == kFatal) {
    WriteToStdErr("SELF-TERMINATING by exiting!!!\n");
    _exit(1);
  }
}

}  // namespace checks_internal
}  // namespace silifuzz

#endif  // defined(SILIFUZZ_BUILD_FOR_NOLIBC)
