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

#include <cstddef>

#include "./util/arch.h"
#include "./util/reg_group_io.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {

// Saves the X86 XState registers. The `src_buffer` points to a XSAVE area on
// memory, and its states are to be saved to `dest_buffer`. An additional
// `tmp_buffer` is a provided to temporarily hold the a XSAVE area.
#if defined(__x86_64__)
extern "C" void SaveX86XState(const void* src_buffer, void* tmp_buffer,
                              RegisterGroupIOBuffer<Host>& dest_buffer);
#endif

// Extend the `ucontext` struct with the extension registers.
// Directly add the `eregs` field for simplicity and avoid frequent memory
// allocation. But this may use a lot of memory. If we run into memory issue
// with tracing or corpus analysis, we should switch to use unique_ptr.
template <typename Arch>
struct ExtUContext : public UContext<Arch> {
  using UContext<Arch>::gregs;
  using UContext<Arch>::fpregs;
  RegisterGroupIOBuffer<Arch> eregs;

  inline bool HasERegs() const;
};

template <>
inline bool ExtUContext<X86_64>::HasERegs() const {
  return eregs.register_groups.GetAVX() || eregs.register_groups.GetAVX512();
}

template <>
inline bool ExtUContext<AArch64>::HasERegs() const {
  return eregs.register_groups.GetSVEVectorWidth() != 0;
}

template <typename Arch>
inline bool operator==(const ExtUContext<Arch>& a, const ExtUContext<Arch>& b) {
  return a.gregs == b.gregs && a.fpregs == b.fpregs &&
         a.eregs.register_groups == b.eregs.register_groups &&
         a.eregs == b.eregs;
}

// Computes the bitwise difference between two register groups and stores the
// result in `diff`. The `eregs.register_groups` field in `a` and `b` must be
// the same, and will be copied to `diff`. Only the active registers specified
// by `a.eregs.register_groups` are considered. Inactive register regions of
// `diff` remain unchanged.
template <typename Arch>
void BitDiff(const ExtUContext<Arch>& a, const ExtUContext<Arch>& b,
             ExtUContext<Arch>& diff);

// Compute which bit change between `from` and `to` as well as the direction of
// the change. "0->1" are reflected in `zero_one` and "1->0" in `one_zero`.
// Unchanged bits between `from` and `to` are not modified in the output
// register groups. The `eregs.register_groups` field in `from` and `to` must be
// the same, and will be copied to the output. Only the active registers
// specified by `from.eregs.register_groups` are considered. Inactive register
// regions of `zero_one` and `one_zero` remain unchanged.
template <typename Arch>
void AccumulateToggle(const ExtUContext<Arch>& from,
                      const ExtUContext<Arch>& to, ExtUContext<Arch>& zero_one,
                      ExtUContext<Arch>& one_zero);

// Counts the number of bits that have been set in the `uctx`. GPR and FPR are
// always counted. Only active extension registers specified by
// `uctx.eregs.register_groups` are considered. Overlapping registers (e.g XMM,
// YMM, and ZMM) are counted only once with the biggest register.
template <typename Arch>
size_t PopCount(const ExtUContext<Arch>& uctx);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_TRACING_EXTENSION_REGISTERS_H_
