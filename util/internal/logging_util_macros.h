// Copyright 2025 The SiliFuzz Authors.
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

// This file contains macros for logging register states used in
// logging_util.cc. This file is not intended to be used outside of
// logging_util.cc.

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_INTERNAL_LOGGING_UTIL_MACROS_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_INTERNAL_LOGGING_UTIL_MACROS_H_

// Macro (vs a function) helps up to easily log the names of the registers
// in LogGRegs(), LogFPRegs(), and LogERegs() below.
#define LOG_ONE_REG(reg_name)                                               \
  if (base == nullptr || regs.reg_name != base->reg_name) {                 \
    (*logger)(logger_arg, #reg_name " = ", HexStr(regs.reg_name),           \
              (log_diff && base != nullptr) ? " want " : "",                \
              (log_diff && base != nullptr) ? HexStr(base->reg_name) : ""); \
  }

#define LOG_INDEXED_REG(reg_name, index)                                     \
  if (base == nullptr || regs.reg_name[index] != base->reg_name[index]) {    \
    (*logger)(                                                               \
        logger_arg, StrCat({#reg_name "[", IntStr(index), "] = "}),          \
        HexStr(regs.reg_name[index]),                                        \
        (log_diff && base != nullptr) ? " want " : "",                       \
        (log_diff && base != nullptr) ? HexStr(base->reg_name[index]) : ""); \
  }

#define LOG_INDEXED_BIG_REG(reg_name, index, size)                            \
  if (base == nullptr ||                                                      \
      memcmp(reinterpret_cast<const uint8_t*>(regs.reg_name) + index * size,  \
             reinterpret_cast<const uint8_t*>(base->reg_name) + index * size, \
             size) != 0) {                                                    \
    (*logger)(                                                                \
        logger_arg, StrCat({#reg_name "[", IntStr(index), "] = "}),           \
        BigHexStr(                                                            \
            {reinterpret_cast<const uint8_t*>(regs.reg_name) + index * size,  \
             size}),                                                          \
        (log_diff && base != nullptr) ? " want " : "",                        \
        (log_diff && base != nullptr)                                         \
            ? BigHexStr({reinterpret_cast<const uint8_t*>(base->reg_name) +   \
                             index * size,                                    \
                         size})                                               \
            : "");                                                            \
  }

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_INTERNAL_LOGGING_UTIL_MACROS_H_
