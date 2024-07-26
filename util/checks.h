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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_CHECKS_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_CHECKS_H_

// This library provides definitions for the error checking CHECK* and DCHECK*
// macros, as well as the error-logging LOG_FATAL, LOG_ERROR, and LOG_DFATAL
// macros.
//
// The provided macros are very similar and almost as easy to use as the
// corresponding ones from absl/log/log.h, but can easily be made to
// function in the nolibc mode of building a binary -- see nolibc.bzl.
//
// This library MUST be used instead of directly including "absl/log/check.h"
// and "absl/log/log.h" in all Silifuzz code.
//
// Definitions are provided for both the normal and the "nolibc" mode of
// building a binary - see nolibc.bzl.
// Note that, unlike in absl/log/log.h, << into CHECK* and DCHECK*
// is not supported.
//
// Code that will go into cc_library_plus_nolibc() or cc_binary_plus_nolibc()
// BUILD rules (and hence being built in the "nolibc" mode) - see nolibc.bzl --
// must use these macros and never any facilities from absl/log/log.h.
//
// For the other Silifuzz code we potentially have a choice: use abls/log or
// use only the macros defined in this header.
//
// Currently we take the second choice but provide no enforcement mechanism.
//

#include <string.h>  // for strlen

#include <utility>  // for std::forward

#if !defined(SILIFUZZ_BUILD_FOR_NOLIBC)
#include "absl/log/check.h"        // IWYU pragma: export
#include "absl/log/log.h"          // IWYU pragma: export
#include "absl/strings/str_cat.h"  // IWYU pragma: export
#endif

#include "absl/base/attributes.h"    // for ABSL_ATTRIBUTE_NORETURN
#include "absl/base/optimization.h"  // for ABSL_PREDICT_*

// ========================================================================= //
// Define LOG_ERROR, LOG_FATAL, and LOG_DFATAL including support
// for the nolibc mode. Also define VLOG_INFO and VLOG_IS_ON.

// LOG_ERROR() logs an error message.
// First argument must be a `const char*` with the essential error text.
// 3 additional arguments if all of `const char*` type will be logged even
// in the nolibc mode, otherwise additional arguments are to be absl::StrCat()ed
// with the first argument and logged (or dropped in the nolibc mode).
#if defined(SILIFUZZ_BUILD_FOR_NOLIBC)
#define LOG_ERROR(...)                                                       \
  do {                                                                       \
    SILIFUZZ_CHECKS_INTERNAL_BASENAME;                                       \
    ::silifuzz::checks_internal::LogError(silifuzz_checks_internal_basename, \
                                          __LINE__, __VA_ARGS__);            \
  } while (false)
#else
#define LOG_ERROR(...)                       \
  do {                                       \
    LOG(ERROR) << absl::StrCat(__VA_ARGS__); \
  } while (false)
#endif

// LOG_INFO() is like LOG_ERROR() but for informational messages.
#if defined(SILIFUZZ_BUILD_FOR_NOLIBC)
#define LOG_INFO(...)                                                       \
  do {                                                                      \
    SILIFUZZ_CHECKS_INTERNAL_BASENAME;                                      \
    ::silifuzz::checks_internal::LogInfo(silifuzz_checks_internal_basename, \
                                         __LINE__, __VA_ARGS__);            \
  } while (false)
#else
#define LOG_INFO(...)                       \
  do {                                      \
    LOG(INFO) << absl::StrCat(__VA_ARGS__); \
  } while (false)
#endif

// LOG_FATAL() does LOG_ERROR() and then crashes the process.
#if defined(SILIFUZZ_BUILD_FOR_NOLIBC)
#define LOG_FATAL(...)                                                       \
  do {                                                                       \
    SILIFUZZ_CHECKS_INTERNAL_BASENAME;                                       \
    ::silifuzz::checks_internal::LogFatal(silifuzz_checks_internal_basename, \
                                          __LINE__, __VA_ARGS__);            \
  } while (false)
#else
#define LOG_FATAL(...)                       \
  do {                                       \
    LOG(FATAL) << absl::StrCat(__VA_ARGS__); \
  } while (false)
#endif

// VLOG_INFO() is like LOG_INFO() but modulated by a verbosity level.
// VLOG_IS_ON() is for explicit VLOG() level testing.
#if defined(SILIFUZZ_BUILD_FOR_NOLIBC)
#define VLOG_IS_ON(level) ((level) <= ::silifuzz::checks_internal::vlog_level)
#endif
#define VLOG_INFO(level, ...) LOG_INFO_IF(VLOG_IS_ON(level), __VA_ARGS__)

// Conditional logging variants.
#define LOG_ERROR_IF(cond, ...)                           \
  do {                                                    \
    if (ABSL_PREDICT_FALSE(cond)) LOG_ERROR(__VA_ARGS__); \
  } while (false)
#define LOG_INFO_IF(cond, ...)                           \
  do {                                                   \
    if (ABSL_PREDICT_FALSE(cond)) LOG_INFO(__VA_ARGS__); \
  } while (false)
#define LOG_FATAL_IF(cond, ...)                           \
  do {                                                    \
    if (ABSL_PREDICT_FALSE(cond)) LOG_FATAL(__VA_ARGS__); \
  } while (false)
#define VLOG_INFO_IF(cond, ...)                           \
  do {                                                    \
    if (ABSL_PREDICT_FALSE(cond)) VLOG_INFO(__VA_ARGS__); \
  } while (false)

// LOG_DFATAL() is like LOG_FATAL() in opt mode and LOG_ERROR() in debug mode.
// Similarly for LOG_DFATAL_IF().
// DVLOG_INFO() is VLOG_INFO() in opt mode and noop in debug mode.
#ifndef NDEBUG
#define LOG_DFATAL LOG_FATAL
#define LOG_DFATAL_IF LOG_FATAL_IF
#define DVLOG_INFO VLOG_INFO
#else
#define LOG_DFATAL LOG_ERROR
#define LOG_DFATAL_IF LOG_ERROR_IF
#define DVLOG_INFO(...)
#endif

// ========================================================================= //
// Provide CHECK*, DCHECK*, and DEBUG_MODE.

#if !defined(SILIFUZZ_BUILD_FOR_NOLIBC)

// absl/log/log.h will provide CHECK*, DCHECK*.
// Also provide DEBUG_MODE.
#ifndef NDEBUG
const bool DEBUG_MODE = true;
#else   // defined(NDEBUG)
const bool DEBUG_MODE = false;
#endif  // defined(NDEBUG)

#define CHECK_LOG(condition, log) CHECK(condition) << (log);
#define CHECK_EQ_LOG(x, y, log) CHECK_EQ(x, y) << (log);
#define CHECK_NE_LOG(x, y, log) CHECK_NE(x, y) << (log);
#define CHECK_LE_LOG(x, y, log) CHECK_LE(x, y) << (log);
#define CHECK_LT_LOG(x, y, log) CHECK_LT(x, y) << (log);
#define CHECK_GE_LOG(x, y, log) CHECK_GE(x, y) << (log);
#define CHECK_GT_LOG(x, y, log) CHECK_GT(x, y) << (log);

#define DCHECK_LOG(condition, log) DCHECK(condition) << (log);
#define DCHECK_EQ_LOG(x, y, log) DCHECK_EQ(x, y) << (log);
#define DCHECK_NE_LOG(x, y, log) DCHECK_NE(x, y) << (log);
#define DCHECK_LE_LOG(x, y, log) DCHECK_LE(x, y) << (log);
#define DCHECK_LT_LOG(x, y, log) DCHECK_LT(x, y) << (log);
#define DCHECK_GE_LOG(x, y, log) DCHECK_GE(x, y) << (log);
#define DCHECK_GT_LOG(x, y, log) DCHECK_GT(x, y) << (log);

#else  // defined(SILIFUZZ_BUILD_FOR_NOLIBC)

// Define simple implementations of CHECK*, DCHECK* (and DEBUG_MODE)
// like in absl/log/log.h that do not need libc when
// defined(SILIFUZZ_BUILD_FOR_NOLIBC), but do not support any << either.

#define CHECK(condition)                                                     \
  while (!(condition)) {                                                     \
    SILIFUZZ_CHECKS_INTERNAL_BASENAME;                                       \
    ::silifuzz::checks_internal::LogFatal(silifuzz_checks_internal_basename, \
                                          __LINE__,                          \
                                          "Check failed: " #condition);      \
  }

#define CHECK_LOG(condition, log)                    \
  while (!(condition)) {                             \
    SILIFUZZ_CHECKS_INTERNAL_BASENAME;               \
    ::silifuzz::checks_internal::LogFatal(           \
        silifuzz_checks_internal_basename, __LINE__, \
        "Check failed: " #condition " ", log);       \
  }

#define CHECK_EQ(x, y) SILIFUZZ_CHECKS_INTERNAL_CHECK_OP(x, ==, y)
#define CHECK_NE(x, y) SILIFUZZ_CHECKS_INTERNAL_CHECK_OP(x, !=, y)
#define CHECK_LE(x, y) SILIFUZZ_CHECKS_INTERNAL_CHECK_OP(x, <=, y)
#define CHECK_LT(x, y) SILIFUZZ_CHECKS_INTERNAL_CHECK_OP(x, <, y)
#define CHECK_GE(x, y) SILIFUZZ_CHECKS_INTERNAL_CHECK_OP(x, >=, y)
#define CHECK_GT(x, y) SILIFUZZ_CHECKS_INTERNAL_CHECK_OP(x, >, y)

#define CHECK_EQ_LOG(x, y, log) \
  SILIFUZZ_CHECKS_INTERNAL_CHECK_OP_LOG(x, ==, y, log)
#define CHECK_NE_LOG(x, y, log) \
  SILIFUZZ_CHECKS_INTERNAL_CHECK_OP_LOG(x, !=, y, log)
#define CHECK_LE_LOG(x, y, log) \
  SILIFUZZ_CHECKS_INTERNAL_CHECK_OP_LOG(x, <=, y, log)
#define CHECK_LT_LOG(x, y, log) \
  SILIFUZZ_CHECKS_INTERNAL_CHECK_OP_LOG(x, <, y, log)
#define CHECK_GE_LOG(x, y, log) \
  SILIFUZZ_CHECKS_INTERNAL_CHECK_OP_LOG(x, >=, y, log)
#define CHECK_GT_LOG(x, y, log) \
  SILIFUZZ_CHECKS_INTERNAL_CHECK_OP_LOG(x, >, y, log)

#ifndef NDEBUG

const bool DEBUG_MODE = true;
#define DCHECK(condition) CHECK(condition)
#define DCHECK_EQ(x, y) CHECK_EQ(x, y)
#define DCHECK_NE(x, y) CHECK_NE(x, y)
#define DCHECK_LE(x, y) CHECK_LE(x, y)
#define DCHECK_LT(x, y) CHECK_LT(x, y)
#define DCHECK_GE(x, y) CHECK_GE(x, y)
#define DCHECK_GT(x, y) CHECK_GT(x, y)

#define DCHECK_LOG(condition, log) CHECK_LOG(condition, log)
#define DCHECK_EQ_LOG(x, y, log) CHECK_EQ_LOG(x, y, log)
#define DCHECK_NE_LOG(x, y, log) CHECK_NE_LOG(x, y, log)
#define DCHECK_LE_LOG(x, y, log) CHECK_LE_LOG(x, y, log)
#define DCHECK_LT_LOG(x, y, log) CHECK_LT_LOG(x, y, log)
#define DCHECK_GE_LOG(x, y, log) CHECK_GE_LOG(x, y, log)
#define DCHECK_GT_LOG(x, y, log) CHECK_GT_LOG(x, y, log)

#else  // defined(NDEBUG)

const bool DEBUG_MODE = false;
#define DCHECK(condition) \
  while (false) {         \
  }
#define DCHECK_EQ(x, y) DCHECK(true)
#define DCHECK_NE(x, y) DCHECK(true)
#define DCHECK_LE(x, y) DCHECK(true)
#define DCHECK_LT(x, y) DCHECK(true)
#define DCHECK_GE(x, y) DCHECK(true)
#define DCHECK_GT(x, y) DCHECK(true)

#define DCHECK_LOG(condition, log) DCHECK(true)
#define DCHECK_EQ_LOG(x, y, log) DCHECK(true)
#define DCHECK_NE_LOG(x, y, log) DCHECK(true)
#define DCHECK_LE_LOG(x, y, log) DCHECK(true)
#define DCHECK_LT_LOG(x, y, log) DCHECK(true)
#define DCHECK_GE_LOG(x, y, log) DCHECK(true)
#define DCHECK_GT_LOG(x, y, log) DCHECK(true)

#endif  // defined(NDEBUG)

#endif  // defined(SILIFUZZ_BUILD_FOR_NOLIBC)

// ========================================================================= //
// Provide the necessary async-signal-safe variants:
// ASS_LOG_INFO, ASS_LOG_ERROR, ASS_LOG_FATAL, ASS_VLOG_INFO, ASS_DVLOG_INFO,
// ASS_LOG_INFO_IF, ASS_CHECK, ASS_DCHECK, ASS_LOG_DFATAL.
//
// CAVEAT: All the ASS_(D)(V)LOG_* macros only take up-to 5 const char* args.

#define ASS_LOG_ERROR(...)                                         \
  do {                                                             \
    SILIFUZZ_CHECKS_INTERNAL_BASENAME;                             \
    ::silifuzz::checks_internal::ASS_LogError(                     \
        silifuzz_checks_internal_basename, __LINE__, __VA_ARGS__); \
  } while (false)
#define ASS_LOG_INFO(...)                                          \
  do {                                                             \
    SILIFUZZ_CHECKS_INTERNAL_BASENAME;                             \
    ::silifuzz::checks_internal::ASS_LogInfo(                      \
        silifuzz_checks_internal_basename, __LINE__, __VA_ARGS__); \
  } while (false)
#define ASS_LOG_FATAL(...)                                         \
  do {                                                             \
    SILIFUZZ_CHECKS_INTERNAL_BASENAME;                             \
    ::silifuzz::checks_internal::ASS_LogFatal(                     \
        silifuzz_checks_internal_basename, __LINE__, __VA_ARGS__); \
  } while (false)
#define ASS_VLOG_INFO(level, ...) \
  ASS_LOG_INFO_IF(VLOG_IS_ON(level), __VA_ARGS__)
#define ASS_LOG_INFO_IF(cond, ...)                           \
  do {                                                       \
    if (ABSL_PREDICT_FALSE(cond)) ASS_LOG_INFO(__VA_ARGS__); \
  } while (false)
#define ASS_CHECK(condition)                         \
  while (!(condition)) {                             \
    SILIFUZZ_CHECKS_INTERNAL_BASENAME;               \
    ::silifuzz::checks_internal::ASS_LogFatal(       \
        silifuzz_checks_internal_basename, __LINE__, \
        "Check failed: " #condition);                \
  }

#ifndef NDEBUG
#define ASS_DCHECK(condition) ASS_CHECK(condition)
#define ASS_LOG_DFATAL ASS_LOG_FATAL
#define ASS_DVLOG_INFO ASS_VLOG_INFO
#else
#define ASS_DCHECK(condition) DCHECK(true)
#define ASS_LOG_DFATAL ASS_LOG_ERROR
#define ASS_DVLOG_INFO(...)
#endif

// ========================================================================= //
// Provide (D)CHECK_AND_USE for checking a condition before using a value.
// A more general variant of ABSL_DIE_IF_NULL. Useful e.g. for precondition
// checks inside field or base class c-tor invocations.

// Essentially a { CHECK(condition); retun value; } lambda invocation.
#define CHECK_AND_USE(condition, value)                                       \
  ::silifuzz::checks_internal::CheckAndReturn(__FILE__, __LINE__, #condition, \
                                              (condition), (value))

#ifndef NDEBUG
#define DCHECK_AND_USE(condition, value) CHECK_AND_USE(condition, value)
#else
#define DCHECK_AND_USE(condition, value) (value)
#endif

// ========================================================================= //
// Provide (D)CHECK_STATUS, RETURN_IF_NOT_OK(_PLUS), and
// ASSIGN_OR_RETURN_IF_NOT_OK(_PLUS) for checking ok-ness of absl::Status.
// Conceptually these depend on absl::Status or absl::StatusOr<T>, but since
// they are macros, only their actual usage, not this file, need to depend
// on absl::Status(Or) libs.

// If `status` (which must be a absl::Status) is not ok, crashes the process.
//
// CHECK_STATUS() is like CHECK_OK() from //util/task/status.h.
// It did not make it into Abseil yet, but we'd like to use it.
//
// We use a different name to avoid collisions in case some Silifuzz code
// happens to transitively include //util/task/status.h.
#if !defined(SILIFUZZ_BUILD_FOR_NOLIBC)
#define CHECK_STATUS(status) CHECK_EQ(status, ::absl::OkStatus())
#else
#define CHECK_STATUS(status)                                         \
  do {                                                               \
    const ::absl::Status status_value = (status);                    \
    if (ABSL_PREDICT_FALSE(!status_value.ok())) {                    \
      SILIFUZZ_CHECKS_INTERNAL_BASENAME;                             \
      ::silifuzz::checks_internal::LogFatal(                         \
          silifuzz_checks_internal_basename, __LINE__,               \
          "Check status failed: ", status_value.ToString().c_str()); \
    }                                                                \
  } while (false)
#endif

#ifndef NDEBUG
#define DCHECK_STATUS(status) CHECK_STATUS(status)
#else
#define DCHECK_STATUS(status) DCHECK(true)
#endif

// If `status` (which must be an absl::Status) is not ok, return it from
// the current function (which must thus have a compatible return type).
//
// RETURN_IF_NOT_OK() is a simpler variant of RETURN_IF_ERROR() from
// //util/task/status_macros.h.
// We use it instead so that we only depend on Abseil.
//
// We use a different name to avoid collisions in case some Silifuzz code
// happens to transitively include //util/task/status_macros.h.
#define RETURN_IF_NOT_OK(status)                  \
  do {                                            \
    const ::absl::Status status_value = (status); \
    if (ABSL_PREDICT_FALSE(!status_value.ok())) { \
      return status_value;                        \
    }                                             \
  } while (false)

// Like RETURN_IF_NOT_OK(), but also prepends `message_prefix` to the returned
// absl::Status error when `status` is not ok.
//
// Note: usage also needs to depend on third_party/absl/strings/str_cat.h.
#define RETURN_IF_NOT_OK_PLUS(status, message_prefix)              \
  do {                                                             \
    const ::absl::Status status_value = (status);                  \
    if (ABSL_PREDICT_FALSE(!status_value.ok())) {                  \
      return ::absl::Status(                                       \
          status_value.code(),                                     \
          ::absl::StrCat(message_prefix, status_value.message())); \
    }                                                              \
  } while (false)

// If `src` (which must be an absl::StatusOr<T>) is not ok, return that status
// from the current function (which must thus have a compatible return type),
// otherwise assign the value in `src` to `dest` (which can be an l-value or
// a variable declaration).
//
// Similarly to RETURN_IF_NOT_OK() above, this is a simpler variant of
// ASSIGN_OR_RETURN() from //util/task/status_macros.h.
#define ASSIGN_OR_RETURN_IF_NOT_OK(dest, src) \
  ASSIGN_OR_RETURN_IF_NOT_OK_IMPL_(           \
      CHECKS_INTERNAL_CONCAT_(value_or_, __LINE__), dest, src)
#define ASSIGN_OR_RETURN_IF_NOT_OK_IMPL_(value_or, dest, src) \
  auto value_or = (src);                                      \
  if (ABSL_PREDICT_FALSE(!value_or.ok())) {                   \
    return std::move(value_or).status();                      \
  }                                                           \
  dest = std::move(value_or).value()

// Like ASSIGN_OR_RETURN_IF_NOT_OK(), but also prepends `message_prefix`
// to the returned absl::Status error when `src` is not ok.
//
// Note: usage also needs to depend on third_party/absl/strings/str_cat.h.
#define ASSIGN_OR_RETURN_IF_NOT_OK_PLUS(dest, src, message_prefix) \
  ASSIGN_OR_RETURN_IF_NOT_OK_PLUS_IMPL_(                           \
      CHECKS_INTERNAL_CONCAT_(value_or_, __LINE__), dest, src, message_prefix)
#define ASSIGN_OR_RETURN_IF_NOT_OK_PLUS_IMPL_(value_or, dest, src,    \
                                              message_prefix)         \
  auto value_or = (src);                                              \
  if (ABSL_PREDICT_FALSE(!value_or.ok())) {                           \
    return ::absl::Status(                                            \
        value_or.status().code(),                                     \
        ::absl::StrCat(message_prefix, value_or.status().message())); \
  }                                                                   \
  dest = std::move(value_or).value()

// Internal helper for concatenating macro values.
#define CHECKS_INTERNAL_CONCAT_IMPL_(x, y) x##y
#define CHECKS_INTERNAL_CONCAT_(x, y) CHECKS_INTERNAL_CONCAT_IMPL_(x, y)

// ========================================================================= //
// Private implementation details of this library.

namespace silifuzz {

// Set VLOG-level controlling the logging verbosity for nolibc/no-absl
// binaries. Does nothing when #!defined (SILIFUZZ_BUILD_FOR_NOLIBC)
void SetVLogLevel(int vlog_level);

namespace checks_internal {

#if defined(SILIFUZZ_BUILD_FOR_NOLIBC)
// Log level boundary for VLOG_INFO()/VLOG_IS_ON().
// We don't support flags for nolibc/no-absl. An alternative mechanism
// of progating this value to the harness must be used then.
//
// A note on thread-safety.
// The access to this variable is not synchronized and we expect the harness
// setup process to remain single-threaded.
extern int vlog_level;
#endif

// Compile-time function to get the "base" filename, that is, the part of
// a filename after the last "/" path separator.  The search starts at
// the end of the string; the second parameter is the length of the string.
// Used by SILIFUZZ_CHECKS_INTERNAL_BASENAME.
inline constexpr const char* Basename(const char* fname, int offset) {
  return offset == 0 || fname[offset - 1] == '/' ? fname + offset
                                                 : Basename(fname, offset - 1);
}

// Convenience helper to declare silifuzz_checks_internal_basename
// that contains the basename part of __FILE__.
//
// This is all done inside macros, not inside LogImpl() in .cc so that
// only the basename parts of the source file names need to be linked
// into the resulting code as string literals.
#define SILIFUZZ_CHECKS_INTERNAL_BASENAME                   \
  constexpr const char* silifuzz_checks_internal_basename = \
      ::silifuzz::checks_internal::Basename(__FILE__, sizeof(__FILE__) - 1)

// Error logging severity.
// Corresponds to LogSeverity in absl including the int values.
enum LogSeverity : char { kInfo = 0, kError = 2, kFatal = 3 };

// Tells if we wanted to put more detials into `message*` args of LogImpl()
// but could not.
enum IsMesssageChopped : char { kChopped, kNotChopped };

// The common low-level logging impementation.
// Is async-signal-safe.
// `message[2345]` go after `message1`.
void LogImpl(LogSeverity severity, const char* file, unsigned int line,
             const char* message1, IsMesssageChopped is_chopped = kNotChopped,
             const char* message2 = "", const char* message3 = "",
             const char* message4 = "", const char* message5 = "");

#if !defined(SILIFUZZ_BUILD_FOR_NOLIBC)

// Implements CHECK_AND_USE().
template <typename T>
inline ABSL_MUST_USE_RESULT T CheckAndReturn(const char* file, int line,
                                             const char* condition, bool cond,
                                             T&& value) {
  if (ABSL_PREDICT_FALSE(!cond)) {
    // We could make the failure message not include current __FILE__:__LINE__
    // if we depended on some internals of absl/log/log.h.
    LOG(FATAL) << "Check condition failed: " << condition << " at "
               << Basename(file, strlen(file)) << ":" << line;
  }
  return std::forward<T>(value);
}

#else  // defined(SILIFUZZ_BUILD_FOR_NOLIBC)

// Implements CHECK_??(x, y): `op` is ==, !=, etc.
#define SILIFUZZ_CHECKS_INTERNAL_CHECK_OP(x, op, y)                            \
  while (!((x)op(y))) {                                                        \
    SILIFUZZ_CHECKS_INTERNAL_BASENAME;                                         \
    ::silifuzz::checks_internal::LogFatal(silifuzz_checks_internal_basename,   \
                                          __LINE__,                            \
                                          "Check failed: " #x " " #op " " #y); \
  }

// Modified version that adds a custom log when the check fails.
#define SILIFUZZ_CHECKS_INTERNAL_CHECK_OP_LOG(x, op, y, log) \
  while (!((x)op(y))) {                                      \
    SILIFUZZ_CHECKS_INTERNAL_BASENAME;                       \
    ::silifuzz::checks_internal::LogFatal(                   \
        silifuzz_checks_internal_basename, __LINE__,         \
        "Check failed: " #x " " #op " " #y " ", log);        \
  }

// LogError() overloads implement LOG_ERROR(...) macro.
inline void LogError(const char* file, unsigned int line, const char* err1,
                     const char* err2 = "", const char* err3 = "",
                     const char* err4 = "", const char* err5 = "") {
  LogImpl(kError, file, line, err1, kNotChopped, err2, err3, err4, err5);
}
template <typename... Ts>
inline void LogError(const char* file, unsigned int line, const char* error,
                     Ts&&... args) {
#if !defined(SILIFUZZ_BUILD_FOR_NOLIBC)
  LogImpl(kError, file, line,
          absl::StrCat(error, std::forward<Ts>(args)...).c_str());
#else
  LogImpl(kError, file, line, error, kChopped);
#endif
}

// LogInfo() overloads implement LOG_INFO(...) macro.
inline void LogInfo(const char* file, unsigned int line, const char* err1,
                    const char* err2 = "", const char* err3 = "",
                    const char* err4 = "", const char* err5 = "") {
  LogImpl(kInfo, file, line, err1, kNotChopped, err2, err3, err4, err5);
}
template <typename... Ts>
inline void LogInfo(const char* file, unsigned int line, const char* error,
                    Ts&&... args) {
#if !defined(SILIFUZZ_BUILD_FOR_NOLIBC)
  LogImpl(kInfo, file, line,
          absl::StrCat(error, std::forward<Ts>(args)...).c_str());
#else
  LogImpl(kInfo, file, line, error, kChopped);
#endif
}

// LogFatal() overloads implement LOG_FATAL(...) macro.
inline ABSL_ATTRIBUTE_NORETURN void LogFatal(
    const char* file, unsigned int line, const char* err1,
    const char* err2 = "", const char* err3 = "", const char* err4 = "",
    const char* err5 = "") {
  LogImpl(kFatal, file, line, err1, kNotChopped, err2, err3, err4, err5);
  __builtin_unreachable();
}
template <typename... Ts>
inline ABSL_ATTRIBUTE_NORETURN void LogFatal(const char* file,
                                             unsigned int line,
                                             const char* error, Ts&&... args) {
#if !defined(SILIFUZZ_BUILD_FOR_NOLIBC)
  LogImpl(kFatal, file, line,
          absl::StrCat(error, std::forward<Ts>(args)...).c_str());
#else
  LogImpl(kFatal, file, line, error, kChopped);
#endif
  __builtin_unreachable();
}

// Implements CHECK_AND_USE().
template <typename T>
inline ABSL_MUST_USE_RESULT T CheckAndReturn(const char* file, int line,
                                             const char* condition, bool cond,
                                             T&& value) {
  if (ABSL_PREDICT_FALSE(!cond)) {
    LogFatal(Basename(file, strlen(file)), line,
             "Check condition failed: ", condition);
  }
  return std::forward<T>(value);
}

#endif  // defined(SILIFUZZ_BUILD_FOR_NOLIBC)

// Implements ASS_LOG_INFO(...) macro.
inline void ASS_LogInfo(const char* file, unsigned int line, const char* err1,
                        const char* err2 = "", const char* err3 = "",
                        const char* err4 = "", const char* err5 = "") {
  LogImpl(kInfo, file, line, err1, kNotChopped, err2, err3, err4, err5);
}

// Implements ASS_LOG_ERROR(...) macro.
inline void ASS_LogError(const char* file, unsigned int line, const char* err1,
                         const char* err2 = "", const char* err3 = "",
                         const char* err4 = "", const char* err5 = "") {
  LogImpl(kError, file, line, err1, kNotChopped, err2, err3, err4, err5);
}

// Implements ASS_LOG_FATAL(...) macro.
inline ABSL_ATTRIBUTE_NORETURN void ASS_LogFatal(
    const char* file, unsigned int line, const char* err1,
    const char* err2 = "", const char* err3 = "", const char* err4 = "",
    const char* err5 = "") {
  LogImpl(kFatal, file, line, err1, kNotChopped, err2, err3, err4, err5);
  __builtin_unreachable();
}

}  // namespace checks_internal
}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_CHECKS_H_
