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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_UCONTEXT_TEST_LIB_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_UCONTEXT_TEST_LIB_H_

#include "./util/ucontext/ucontext.h"

namespace silifuzz {

// Returns true iff all segment registers in `actual` have the same values as
// the corresponding registers in `expected`.
bool HasSameSegmentRegisters(const GRegSet<X86_64>& actual,
                             const GRegSet<X86_64>& expected);

// Returns true iff `ucontext` has the same CS and SS segment register values
// as the current cpu state and thus RestoreUContext() not restoring the two
// segment register values is fine.
// Has simple, not most-efficient impl: meant for (D)CHECK-s.
bool HasCurrentSegmentRegisters(const UContext<X86_64>& ucontext);

// The test value for the register for the TestOneRegister_<reg>() functions.
extern int64_t test_reg_value;

// TestOneRegister_<reg>() tests that SaveUContext() and RestoreUContext()
// indeed can save and restore register <reg> to the right spot in UContext.
//
// The value to test this with is taken from test_reg_value.
// We do not make it a function arg so that there's no register manipulation
// when calling a TestOneRegister_<reg>() and all registers in it are free.
#define DECLARE_TEST_ONE_REGISTER(reg_name) void TestOneRegister_##reg_name();

DECLARE_TEST_ONE_REGISTER(r8)
DECLARE_TEST_ONE_REGISTER(r9)
DECLARE_TEST_ONE_REGISTER(r10)
DECLARE_TEST_ONE_REGISTER(r11)
DECLARE_TEST_ONE_REGISTER(r12)
DECLARE_TEST_ONE_REGISTER(r13)
DECLARE_TEST_ONE_REGISTER(r14)
DECLARE_TEST_ONE_REGISTER(r15)
DECLARE_TEST_ONE_REGISTER(rdi)
DECLARE_TEST_ONE_REGISTER(rsi)
DECLARE_TEST_ONE_REGISTER(rbp)
DECLARE_TEST_ONE_REGISTER(rbx)
DECLARE_TEST_ONE_REGISTER(rdx)
DECLARE_TEST_ONE_REGISTER(rax)
DECLARE_TEST_ONE_REGISTER(rcx)

#undef DECLARE_TEST_ONE_REGISTER

// This is similar to TestOneRegister_<reg>(), but provides one special-cased
// test for the rsp and rip registers -- we can't freely modify those registers.
void TestSpecialRegisters_rsp_rip();

// This is similar to TestOneRegister_<reg>(), but tests various other
// parts of UContext: segment registers, eflags, sigmask, and fp registers.
void TestUContextVarious();

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_UCONTEXT_TEST_LIB_H_
