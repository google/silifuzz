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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_FLAG_MATCHER_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_FLAG_MATCHER_H_

#include "./util/checks.h"

namespace silifuzz {

// Simple command line flag matcher.
//
// This accepts command line flags of the following forms:
//   --<flag>
//   --<flag> <arg>
//   --<flag>=<arg>
//
// For simplicity, we assume all command line flags preceed non-flag options.
//
// Example usage:
//
// int main(int argc, char* argv[]) {
//   ...
//   CommandLineFlagMatcher matcher(argc, argv);
//   while (true) {
//     if (matcher.Match("flag1", kNoArgument)) {
//       ...
//     else if (matcher.Match("flag2", kRequiredArgument)) {
//       ...
//     } else {
//       break;  // unrecognized command line option.
//     }
//
//   }
// This class is thread-compatible.
//
class CommandLineFlagMatcher {
 public:
  enum ArgumentKind {
    kNoArgument = 0,        // flag does not have an argument
    kRequiredArgument = 1,  // flag requires an argument
  };

  // Construct a CommanLineFlagMatcher object. 'argv[]' is an array of
  // 'argc' elements that are similar to the one passed to main().
  // The first element of the array is ignored and matching begins at
  // the second elements.
  // REQUIRES: argc > 1 and argv != nullptr.
  CommandLineFlagMatcher(int argc, const char* const* argv)
      : argc_(argc), argv_(argv), optind_(1), optarg_(nullptr) {
    DCHECK_GT(argc, 0);
    DCHECK_NE(argv, nullptr);
  }

  ~CommandLineFlagMatcher() = default;

  // Movable but not copyable.
  CommandLineFlagMatcher(const CommandLineFlagMatcher&) = delete;
  CommandLineFlagMatcher(CommandLineFlagMatcher&&) = default;
  CommandLineFlagMatcher& operator=(const CommandLineFlagMatcher&) = delete;
  CommandLineFlagMatcher& operator=(CommandLineFlagMatcher&&) = default;

  // Returns index of the next command line option to match.
  int optind() const { return optind_; }

  // Returns a pointer of the optional argument of the last
  // successful Match() call or nullptr if there is none.
  const char* optarg() const { return optarg_; }

  // Determines if the next unconsumed command line option is 'flag'
  // with an 'argument_kind' optional argument. See ArgumentKind enum definition
  // above for details of argument kinds. If the next unconsumed argument
  // matches 'flag, returns true and also advances state of this so that value
  // returned by optind() is after 'flag' and the optional argument if
  // specified. Otherwise returns false.

  bool Match(const char* flag, ArgumentKind argument_kind);

 private:
  // Number of command line arguments passed to constructor.
  const int argc_;

  // Command line argument array passed to constructor.
  // argv[] in main is an array of non-cost pointer.  This has to be const
  // pointer to const char pointers for implicit conversion to work correctly.
  const char* const* argv_;

  // Index of the next command line option to match.  This is
  // initialized to be 1 at construction. Match() advances this.
  int optind_;

  // Pointer to the optional argument of the last successful match.
  // It is nullptr if the last matched option does not have an argument.
  const char* optarg_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_FLAG_MATCHER_H_
