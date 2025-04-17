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

#include "./util/itoa.h"

#include <string.h>

#include <csignal>
#include <cstdint>
#include <limits>

#include "./util/checks.h"

namespace silifuzz {

namespace itoa_internal {

static const char kHexCharMap[] = "0123456789abcdef";

IntStr::IntStr(int64_t num) { ptr_ = checks_internal::IntStr(num, rep_); }

ErrnoStr::ErrnoStr(int num) : IntStr(num) {
  static constexpr char prefix[] = "errno=";
  constexpr size_t prefix_len = sizeof(prefix) - 1;
  // digits10 is the floor, we want ceil. +1 is a conservative approximation.
  constexpr auto max_digits = std::numeric_limits<decltype(num)>::digits10 + 1;
  static_assert(sizeof(rep_) >= prefix_len + max_digits + 2,
                "Increase size of rep_");
  // The IntStr constructor should have turned the integer into a string, now
  // prepend a prefix.
  ptr_ -= prefix_len;
  memcpy(ptr_, prefix, prefix_len);
}

// ========================================================================= //

// Impl is borrowed from absl::substitute_internal::Arg::Arg(const void* value).
HexStr::HexStr(__uint128_t num) {
  static_assert(sizeof(rep_) >= sizeof(num) * 2 + 3, "Increase size of rep_");
  ptr_ = rep_ + sizeof(rep_);
  *--ptr_ = '\0';
  do {
    *--ptr_ = kHexCharMap[num & 0xf];
    num >>= 4;
  } while (num != 0);
  *--ptr_ = 'x';
  *--ptr_ = '0';
}

}  // namespace itoa_internal

// ========================================================================= //

const char* BoolStr(bool b) { return b ? "true" : "false"; }

// ========================================================================= //

const char* SignalNameStr(int signal) {
  // System-defined signals in the order they are listed by `kill -l`.
  switch (signal) {
      // clang-format off
    case SIGHUP:          return "SIGHUP";
    case SIGINT:          return "SIGINT";
    case SIGQUIT:         return "SIGQUIT";
    case SIGILL:          return "SIGILL";
    case SIGTRAP:         return "SIGTRAP";
    case SIGABRT:         return "SIGABRT";
    case SIGBUS:          return "SIGBUS";
    case SIGFPE:          return "SIGFPE";
    case SIGKILL:         return "SIGKILL";
    case SIGUSR1:         return "SIGUSR1";
    case SIGSEGV:         return "SIGSEGV";
    case SIGUSR2:         return "SIGUSR2";
    case SIGPIPE:         return "SIGPIPE";
    case SIGALRM:         return "SIGALRM";
    case SIGTERM:         return "SIGTERM";
    case SIGSTKFLT:       return "SIGSTKFLT";
    case SIGCHLD:         return "SIGCHLD";
    case SIGSTOP:         return "SIGSTOP";
    case SIGCONT:         return "SIGCONT";
    case SIGTSTP:         return "SIGTSTP";
    case SIGTTIN:         return "SIGTTIN";
    case SIGTTOU:         return "SIGTTOU";
    case SIGURG:          return "SIGURG";
    case SIGXCPU:         return "SIGXCPU";
    case SIGXFSZ:         return "SIGXFSZ";
    case SIGVTALRM:       return "SIGVTALRM";
    case SIGPROF:         return "SIGPROF";
    case SIGWINCH:        return "SIGWINCH";
    case SIGIO:           return "SIGIO";
    case SIGPWR:          return "SIGPWR";
    case SIGSYS:          return "SIGSYS";
      // clang-format on
  }
  // Real-time signals (cf. `man signal.7`, 'Real-time signals').
  switch (signal) {
    // clang-format off
    // NOTE: Generally speaking, the actual values are platform-dependent, but
    // we use the actual values in Google runtime.
    static_assert(__SIGRTMIN == 32, "Unexpected __SIGRTMIN");
    case __SIGRTMIN + 0:  return "__SIGRTMIN+0";
    case __SIGRTMIN + 1:  return "__SIGRTMIN+1";
    case __SIGRTMIN + 2:  return "__SIGRTMIN+2";
    case __SIGRTMIN + 3:  return "__SIGRTMIN+3";
    case __SIGRTMIN + 4:  return "__SIGRTMIN+4";
    case __SIGRTMIN + 5:  return "__SIGRTMIN+5";
    case __SIGRTMIN + 6:  return "__SIGRTMIN+6";
    case __SIGRTMIN + 7:  return "__SIGRTMIN+7";
    case __SIGRTMIN + 8:  return "__SIGRTMIN+8";
    case __SIGRTMIN + 9:  return "__SIGRTMIN+9";
    case __SIGRTMIN + 10: return "__SIGRTMIN+10";
    case __SIGRTMIN + 11: return "__SIGRTMIN+11";
    case __SIGRTMIN + 12: return "__SIGRTMIN+12";
    case __SIGRTMIN + 13: return "__SIGRTMIN+13";
    case __SIGRTMIN + 14: return "__SIGRTMIN+14";
    case __SIGRTMIN + 15: return "__SIGRTMIN+15";
    case __SIGRTMIN + 16: return "__SIGRTMIN+16";
    case __SIGRTMIN + 17: return "__SIGRTMIN+17";
    case __SIGRTMIN + 18: return "__SIGRTMIN+18";
    case __SIGRTMIN + 19: return "__SIGRTMIN+19";
    case __SIGRTMIN + 20: return "__SIGRTMIN+20";
    case __SIGRTMIN + 21: return "__SIGRTMIN+21";
    case __SIGRTMIN + 22: return "__SIGRTMIN+22";
    case __SIGRTMIN + 23: return "__SIGRTMIN+23";
    case __SIGRTMIN + 24: return "__SIGRTMIN+24";
    case __SIGRTMIN + 25: return "__SIGRTMIN+25";
    case __SIGRTMIN + 26: return "__SIGRTMIN+26";
    case __SIGRTMIN + 27: return "__SIGRTMIN+27";
    case __SIGRTMIN + 28: return "__SIGRTMIN+28";
    case __SIGRTMIN + 29: return "__SIGRTMIN+29";
    case __SIGRTMIN + 30: return "__SIGRTMIN+30";
    case __SIGRTMIN + 31: return "__SIGRTMIN+31";
    case __SIGRTMIN + 32: return "__SIGRTMIN+32";
    static_assert(__SIGRTMIN + 32 == __SIGRTMAX, "Unexpected __SIGRTMAX");
      // clang-format on
  }
  return "UNKNOWN SIGNAL";
}

}  // namespace silifuzz
