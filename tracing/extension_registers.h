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
#ifndef THIRD_PARTY_SILIFUZZ_TRACING_EXTENSION_REGISTERS_H_
#define THIRD_PARTY_SILIFUZZ_TRACING_EXTENSION_REGISTERS_H_

#include <sys/types.h>

#include "./util/arch.h"
#include "./util/reg_group_io.h"

namespace silifuzz {

// Saves the X86 XState registers. The `src_buffer` points to a XSAVE area on
// memory, and its states are to be saved to `dest_buffer`. An additional
// `tmp_buffer` is a provided to temporarily hold the a XSAVE area.
#if defined(__x86_64__)
extern "C" void SaveX86XState(const void* src_buffer, void* tmp_buffer,
                              RegisterGroupIOBuffer<Host>& dest_buffer);
#endif
}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_TRACING_EXTENSION_REGISTERS_H_
