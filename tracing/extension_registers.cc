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

#include "./tracing/extension_registers.h"

#include <sys/types.h>

#include <cstddef>

#include "./util/arch.h"
#include "./util/bitops.h"
#include "./util/checks.h"
#include "./util/reg_group_io.h"
#include "./util/sve_constants.h"

namespace silifuzz {

namespace {

// Computes the bitwise difference between two register groups and stores the
// result in `diff`. The `register_groups` field in `a` and `b` must be the
// same, and will be copied to `diff`. Only the active registers specified by
// `register_groups` are considered. Inactive register regions of `diff` remain
// unchanged.
template <typename Arch>
void RegGroupBitDiff(const RegisterGroupIOBuffer<Arch>& a,
                     const RegisterGroupIOBuffer<Arch>& b,
                     RegisterGroupIOBuffer<Arch>& diff);

template <>
void RegGroupBitDiff(const RegisterGroupIOBuffer<X86_64>& a,
                     const RegisterGroupIOBuffer<X86_64>& b,
                     RegisterGroupIOBuffer<X86_64>& diff) {
  CHECK(a.register_groups == b.register_groups);
  diff.register_groups = a.register_groups;
  if (a.register_groups.GetAVX()) {
    BitDiff(a.ymm, b.ymm, diff.ymm);
  }
  if (a.register_groups.GetAVX512()) {
    BitDiff(a.zmm, b.zmm, diff.zmm);
    BitDiff(a.opmask, b.opmask, diff.opmask);
  }
}

template <>
void RegGroupBitDiff(const RegisterGroupIOBuffer<AArch64>& a,
                     const RegisterGroupIOBuffer<AArch64>& b,
                     RegisterGroupIOBuffer<AArch64>& diff) {
  CHECK(a.register_groups == b.register_groups);
  diff.register_groups = a.register_groups;
  const size_t vl = a.register_groups.GetSVEVectorWidth();
  if (vl == 0) {
    return;
  }

  BitDiff(a.z, b.z, SveZRegActiveSizeBytes(vl), diff.z);
  // P registers can be as small as 32 bytes.
  BitDiff(a.p, b.p, SvePRegActiveSizeBytes(vl), diff.p);
  // FFR can be as small as 2 bytes.
  BitDiff(a.ffr, b.ffr, SveFfrActiveSizeBytes(vl), diff.ffr);
}

// Compute which bit change between `from` and `to` as well as the direction of
// the change. "0->1" are reflected in `zero_one` and "1->0" in `one_zero`.
// Unchanged bits between `from` and `to` are not modified in the output
// register groups. The `register_groups` field in `from` and `to` must be the
// same, and will be copied to the output. Only the active registers specified
// by `register_groups` are considered. Inactive register regions of `zero_one`
// and `one_zero` remain unchanged.
template <typename Arch>
void RegGroupAccumulateToggle(const RegisterGroupIOBuffer<Arch>& from,
                              const RegisterGroupIOBuffer<Arch>& to,
                              RegisterGroupIOBuffer<Arch>& zero_one,
                              RegisterGroupIOBuffer<Arch>& one_zero);

template <>
void RegGroupAccumulateToggle(const RegisterGroupIOBuffer<X86_64>& from,
                              const RegisterGroupIOBuffer<X86_64>& to,
                              RegisterGroupIOBuffer<X86_64>& zero_one,
                              RegisterGroupIOBuffer<X86_64>& one_zero) {
  CHECK(from.register_groups == to.register_groups);
  zero_one.register_groups = from.register_groups;
  one_zero.register_groups = from.register_groups;
  if (from.register_groups.GetAVX()) {
    AccumulateToggle(from.ymm, to.ymm, zero_one.ymm, one_zero.ymm);
  }
  if (from.register_groups.GetAVX512()) {
    AccumulateToggle(from.zmm, to.zmm, zero_one.zmm, one_zero.zmm);
    AccumulateToggle(from.opmask, to.opmask, zero_one.opmask, one_zero.opmask);
  }
}

template <>
void RegGroupAccumulateToggle(const RegisterGroupIOBuffer<AArch64>& from,
                              const RegisterGroupIOBuffer<AArch64>& to,
                              RegisterGroupIOBuffer<AArch64>& zero_one,
                              RegisterGroupIOBuffer<AArch64>& one_zero) {
  CHECK(from.register_groups == to.register_groups);
  zero_one.register_groups = from.register_groups;
  one_zero.register_groups = from.register_groups;
  const size_t vl = from.register_groups.GetSVEVectorWidth();
  if (vl == 0) {
    return;
  }
  AccumulateToggle(from.z, to.z, SveZRegActiveSizeBytes(vl), zero_one.z,
                   one_zero.z);
  AccumulateToggle(from.p, to.p, SvePRegActiveSizeBytes(vl), zero_one.p,
                   one_zero.p);
  AccumulateToggle(from.ffr, to.ffr, SveFfrActiveSizeBytes(vl), zero_one.ffr,
                   one_zero.ffr);
}

// Counts the number of bits that have been set in the register group. Only the
// active registers specified by `register_groups` are considered. Overlapping
// registers are counted only once with the largest register.
template <typename Arch>
size_t RegGroupBitCount(const RegisterGroupIOBuffer<Arch>& buffer);

template <>
size_t RegGroupBitCount(const RegisterGroupIOBuffer<X86_64>& buffer) {
  size_t count = 0;
  if (buffer.register_groups.GetAVX() && !buffer.register_groups.GetAVX512()) {
    // YMM registers are the alias of lower bits of ZMM registers. Count only
    // the AVX512 not enabled.
    count += PopCount(buffer.ymm);
  }
  if (buffer.register_groups.GetAVX512()) {
    count += PopCount(buffer.zmm);
    count += PopCount(buffer.opmask);
  }
  return count;
}

template <>
size_t RegGroupBitCount(const RegisterGroupIOBuffer<AArch64>& buffer) {
  const size_t vl = buffer.register_groups.GetSVEVectorWidth();
  if (vl == 0) {
    return 0;
  }
  return PopCount(buffer.z, SveZRegActiveSizeBytes(vl)) +
         PopCount(buffer.p, SvePRegActiveSizeBytes(vl)) +
         PopCount(buffer.ffr, SveFfrActiveSizeBytes(vl));
}

}  // namespace

template <typename Arch>
void BitDiff(const ExtUContext<Arch>& a, const ExtUContext<Arch>& b,
             ExtUContext<Arch>& diff) {
  CHECK(a.eregs.register_groups == b.eregs.register_groups);
  BitDiff(a.gregs, b.gregs, diff.gregs);
  BitDiff(a.fpregs, b.fpregs, diff.fpregs);
  RegGroupBitDiff(a.eregs, b.eregs, diff.eregs);
}

template <typename Arch>
void AccumulateToggle(const ExtUContext<Arch>& from,
                      const ExtUContext<Arch>& to, ExtUContext<Arch>& zero_one,
                      ExtUContext<Arch>& one_zero) {
  CHECK(to.eregs.register_groups == from.eregs.register_groups);

  AccumulateToggle(from.gregs, to.gregs, zero_one.gregs, one_zero.gregs);
  AccumulateToggle(from.fpregs, to.fpregs, zero_one.fpregs, one_zero.fpregs);
  RegGroupAccumulateToggle(from.eregs, to.eregs, zero_one.eregs,
                           one_zero.eregs);
}

template <>
size_t PopCount(const ExtUContext<X86_64>& uctx) {
  size_t count = PopCount(uctx.gregs) + PopCount(uctx.fpregs);
  if (uctx.HasERegs()) {
    // YMM/ZMM registers lower 128 bits are the alias of XMM registers.
    return count + RegGroupBitCount(uctx.eregs) - PopCount(uctx.fpregs.xmm);
  }
  return count;
}

template <>
size_t PopCount(const ExtUContext<AArch64>& uctx) {
  size_t count = PopCount(uctx.gregs) + PopCount(uctx.fpregs);
  if (uctx.HasERegs()) {
    // Z registers lower 128 bits are the alias of V registers.
    return count + RegGroupBitCount(uctx.eregs) - PopCount(uctx.fpregs.v);
  }
  return count;
}

template void BitDiff(const ExtUContext<X86_64>& a,
                      const ExtUContext<X86_64>& b, ExtUContext<X86_64>& diff);
template void BitDiff(const ExtUContext<AArch64>& a,
                      const ExtUContext<AArch64>& b,
                      ExtUContext<AArch64>& diff);

template void AccumulateToggle(const ExtUContext<X86_64>& from,
                               const ExtUContext<X86_64>& to,
                               ExtUContext<X86_64>& zero_one,
                               ExtUContext<X86_64>& one_zero);
template void AccumulateToggle(const ExtUContext<AArch64>& from,
                               const ExtUContext<AArch64>& to,
                               ExtUContext<AArch64>& zero_one,
                               ExtUContext<AArch64>& one_zero);

}  // namespace silifuzz
