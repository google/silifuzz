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

#include "./instruction/decoded_insn.h"

#include <sys/user.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/statusor.h"
#include "absl/strings/ascii.h"
#include "absl/strings/string_view.h"
#include "./util/testing/status_matchers.h"

extern "C" {
#include "third_party/libxed/xed-reg-enum.h"
};

namespace silifuzz {

// Test peer for DecodedInsn.  Currently only used for accessing
// static internal methods.
class DecodedInsnTestPeer {
 public:
  explicit DecodedInsnTestPeer(DecodedInsn& insn) : insn_(insn) {}
  ~DecodedInsnTestPeer() = default;

  // Copyable and movable.
  DecodedInsnTestPeer(const DecodedInsnTestPeer&) = default;
  DecodedInsnTestPeer& operator=(const DecodedInsnTestPeer&) = default;
  DecodedInsnTestPeer(DecodedInsnTestPeer&&) = default;
  DecodedInsnTestPeer& operator=(DecodedInsnTestPeer&&) = default;

  static absl::StatusOr<uint64_t> get_reg(
      xed_reg_enum_t reg, const struct user_regs_struct& context) {
    return DecodedInsn::get_reg(reg, context);
  }
  absl::StatusOr<uint64_t> memory_operand_address(
      size_t i, const struct user_regs_struct& regs) {
    return insn_.memory_operand_address(i, regs);
  }
  std::string get_raw_bytes() { return insn_.raw_bytes_; }

 private:
  DecodedInsn& insn_;  // class under test
};

namespace {

using silifuzz::testing::IsOkAndHolds;

TEST(DecodedInsn, Nop) {
  DecodedInsn insn("\x90");
  ASSERT_TRUE(insn.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn.DebugString()), "nop");
  EXPECT_TRUE(insn.is_allowed_in_runner());
  EXPECT_FALSE(insn.is_locking());
  EXPECT_EQ(insn.length(), 1);
}

TEST(DecodedInsn, CpuId) {
  DecodedInsn insn("\x0f\xa2");
  ASSERT_TRUE(insn.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn.DebugString()), "cpuid");
  EXPECT_FALSE(insn.is_allowed_in_runner());
  EXPECT_FALSE(insn.is_locking());
  EXPECT_EQ(insn.length(), 2);
}

TEST(DecodedInsn, LockAdd) {
  DecodedInsn insn("\xf0\x83\x04\x24\x01");
  ASSERT_TRUE(insn.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn.DebugString()),
            "lock add dword ptr [rsp], 0x1");
  EXPECT_TRUE(insn.is_allowed_in_runner());
  EXPECT_TRUE(insn.is_locking());
  EXPECT_EQ(insn.length(), 5);
}

TEST(DecodedInsn, XchgbAhAl) {
  DecodedInsn insn("\x86\xc4");
  ASSERT_TRUE(insn.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn.DebugString()), "xchg ah, al");
  EXPECT_TRUE(insn.is_allowed_in_runner());
  EXPECT_FALSE(insn.is_locking());
  EXPECT_EQ(insn.length(), 2);
}

TEST(DecodedInsn, XchgbEaxMem) {
  DecodedInsn insn("\x87\x04\x24");
  ASSERT_TRUE(insn.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn.DebugString()),
            "xchg dword ptr [rsp], eax");
  EXPECT_TRUE(insn.is_allowed_in_runner());
  EXPECT_TRUE(insn.is_locking());
  EXPECT_EQ(insn.length(), 3);
}

TEST(DecodedInsn, LockAddEaxEbx) {
  // Adding a LOCK prefix for register only instruction is non-sensical.
  // XED will reject this as undecodable.
  DecodedInsn insn("\xf0\x01\xc3");  // lock addl %eax, %ebx
  EXPECT_FALSE(insn.is_valid());     // bad lock prefix
}

TEST(DecodedInsn, Invalid) {
  DecodedInsn insn("\xf0\x0f");
  ASSERT_FALSE(insn.is_valid());
}

TEST(DecodedInsn, get_reg) {
  // Construct 64 test values for GPRs. Top 5 bits of each byte encode a
  // register ID and the low 3 bits encode the byte position.
  auto GenTestValue = [](int reg) {
    reg &= (0x1f << 3);
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
      const uint64_t byte = reg | i;
      value |= byte << (i * 8);
    }
    return value;
  };

  // These value can be accessed in different sizes.

  // bytes, high byte, word, dword and qword.
  const uint64_t kRAXValue = GenTestValue(0);
  const uint64_t kRCXValue = GenTestValue(1);
  const uint64_t kRDXValue = GenTestValue(2);
  const uint64_t kRBXValue = GenTestValue(3);

  // bytes, word, dword and qword.
  const uint64_t kRSPValue = GenTestValue(4);
  const uint64_t kRBPValue = GenTestValue(5);
  const uint64_t kRSIValue = GenTestValue(6);
  const uint64_t kRDIValue = GenTestValue(7);
  const uint64_t kR8Value = GenTestValue(8);
  const uint64_t kR9Value = GenTestValue(9);
  const uint64_t kR10Value = GenTestValue(10);
  const uint64_t kR11Value = GenTestValue(11);
  const uint64_t kR12Value = GenTestValue(12);
  const uint64_t kR13Value = GenTestValue(13);
  const uint64_t kR14Value = GenTestValue(14);
  const uint64_t kR15Value = GenTestValue(15);

  // word, dword and qword.
  const uint64_t kRIPValue = GenTestValue(16);

  // qword only.
  const uint64_t kFSBaseValue = GenTestValue(17);
  const uint64_t kGSBaseValue = GenTestValue(18);

  struct user_regs_struct regs{};
  regs.rax = kRAXValue;
  regs.rcx = kRCXValue;
  regs.rdx = kRDXValue;
  regs.rbx = kRBXValue;
  regs.rsp = kRSPValue;
  regs.rbp = kRBPValue;
  regs.rsi = kRSIValue;
  regs.rdi = kRDIValue;
  regs.r8 = kR8Value;
  regs.r9 = kR9Value;
  regs.r10 = kR10Value;
  regs.r11 = kR11Value;
  regs.r12 = kR12Value;
  regs.r13 = kR13Value;
  regs.r14 = kR14Value;
  regs.r15 = kR15Value;
  regs.rip = kRIPValue;
  regs.fs_base = kFSBaseValue;
  regs.gs_base = kGSBaseValue;

  const std::vector<uint64_t> expected_full_reg_values = {
      kRAXValue, kRCXValue, kRDXValue,    kRBXValue,   kRSPValue,
      kRBPValue, kRSIValue, kRDIValue,    kR8Value,    kR9Value,
      kR10Value, kR11Value, kR12Value,    kR13Value,   kR14Value,
      kR15Value, kRIPValue, kFSBaseValue, kGSBaseValue};

  auto test_regs = [&regs, &expected_full_reg_values](
                       std::function<uint64_t(uint64_t)> extractor,
                       const std::vector<xed_reg_enum_t>& reg_enums) {
    ASSERT_LE(reg_enums.size(), expected_full_reg_values.size());
    for (int i = 0; i < reg_enums.size(); ++i) {
      EXPECT_THAT(DecodedInsnTestPeer::get_reg(reg_enums[i], regs),
                  IsOkAndHolds(extractor(expected_full_reg_values[i])))
          << xed_reg_enum_t2str(reg_enums[i]);
    }
  };

  auto get_low_byte = [](uint64_t value) { return value & 0xffUL; };
  const std::vector<xed_reg_enum_t> low_byte_regs = {
      XED_REG_AL,   XED_REG_CL,   XED_REG_DL,   XED_REG_BL,
      XED_REG_SPL,  XED_REG_BPL,  XED_REG_SIL,  XED_REG_DIL,
      XED_REG_R8B,  XED_REG_R9B,  XED_REG_R10B, XED_REG_R11B,
      XED_REG_R12B, XED_REG_R13B, XED_REG_R14B, XED_REG_R15B};
  test_regs(get_low_byte, low_byte_regs);

  auto get_high_byte = [](uint64_t value) { return (value >> 8) & 0xffUL; };
  const std::vector<xed_reg_enum_t> high_byte_regs = {XED_REG_AH, XED_REG_CH,
                                                      XED_REG_DH, XED_REG_BH};
  test_regs(get_high_byte, high_byte_regs);

  auto get_word = [](uint64_t value) { return value & 0xffffUL; };
  const std::vector<xed_reg_enum_t> word_regs = {
      XED_REG_AX,   XED_REG_CX,   XED_REG_DX,   XED_REG_BX,   XED_REG_SP,
      XED_REG_BP,   XED_REG_SI,   XED_REG_DI,   XED_REG_R8W,  XED_REG_R9W,
      XED_REG_R10W, XED_REG_R11W, XED_REG_R12W, XED_REG_R13W, XED_REG_R14W,
      XED_REG_R15W, XED_REG_IP};
  test_regs(get_word, word_regs);

  auto get_dword = [](uint64_t value) { return value & 0xffffffffUL; };
  const std::vector<xed_reg_enum_t> dword_regs = {
      XED_REG_EAX,  XED_REG_ECX,  XED_REG_EDX,  XED_REG_EBX,  XED_REG_ESP,
      XED_REG_EBP,  XED_REG_ESI,  XED_REG_EDI,  XED_REG_R8D,  XED_REG_R9D,
      XED_REG_R10D, XED_REG_R11D, XED_REG_R12D, XED_REG_R13D, XED_REG_R14D,
      XED_REG_R15D, XED_REG_EIP};
  test_regs(get_dword, dword_regs);

  auto get_qword = [](uint64_t value) { return value; };
  const std::vector<xed_reg_enum_t> qword_regs = {
      XED_REG_RAX, XED_REG_RCX, XED_REG_RDX,    XED_REG_RBX,   XED_REG_RSP,
      XED_REG_RBP, XED_REG_RSI, XED_REG_RDI,    XED_REG_R8,    XED_REG_R9,
      XED_REG_R10, XED_REG_R11, XED_REG_R12,    XED_REG_R13,   XED_REG_R14,
      XED_REG_R15, XED_REG_RIP, XED_REG_FSBASE, XED_REG_GSBASE};
  test_regs(get_qword, qword_regs);
}

TEST(DecodedInsn, memory_operand_address) {
  DecodedInsn insn("\x64\x83\x44\x86\x78\x01");
  ASSERT_TRUE(insn.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn.DebugString()),
            "add dword ptr fs:[rsi+rax*4+0x78], 0x1");
  struct user_regs_struct regs{};
  regs.fs_base = 0x12000000;
  regs.rsi = 0x340000;
  regs.rax = 0x5600 >> 2;
  DecodedInsnTestPeer peer(insn);
  EXPECT_THAT(peer.memory_operand_address(0, regs), IsOkAndHolds(0x12345678));

  // Also test a segment that is not FS/GS.
  DecodedInsn insn2("\x26\x48\x8b\x01");  // 0x26 is ES override.
  ASSERT_TRUE(insn2.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn2.DebugString()),
            "mov rax, qword ptr [rcx]");
  regs.es = 0xff;  // This should have no effect on the address.
  regs.rcx = 0xabcdef00;
  DecodedInsnTestPeer peer2(insn2);
  EXPECT_THAT(peer2.memory_operand_address(0, regs), IsOkAndHolds(regs.rcx));

  // RIP relative addressing. Check that RIP value is adjusted correctly
  // for address calculation.
  DecodedInsn insn3(absl::string_view("\x48\x8b\x05\x00\x00\x00\x00", 7));
  ASSERT_TRUE(insn3.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn3.DebugString()),
            "mov rax, qword ptr [rip]");
  regs.rip = 0x1000;
  DecodedInsnTestPeer peer3(insn3);
  EXPECT_THAT(peer3.memory_operand_address(0, regs),
              IsOkAndHolds(regs.rip + insn3.length()));
}

TEST(DecodedInsn, may_have_split_lock) {
  DecodedInsn insn("\xf0\x83\x44\x86\x78\x01");
  ASSERT_TRUE(insn.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn.DebugString()),
            "lock add dword ptr [rsi+rax*4+0x78], 0x1");
  struct user_regs_struct regs{};
  regs.rsi = 0x340000;
  regs.rax = 0x5600 >> 2;
  // Address: 0x345678
  EXPECT_THAT(insn.may_have_split_lock(regs), IsOkAndHolds(false));

  regs.rsi += 4;
  // Address: 0x34567c, just touching cache boundary.
  EXPECT_THAT(insn.may_have_split_lock(regs), IsOkAndHolds(false));

  regs.rsi += 1;
  // Address: 0x34567d, crossing cache boundary.
  EXPECT_THAT(insn.may_have_split_lock(regs), IsOkAndHolds(true));

  DecodedInsn insn2("\x83\x44\x86\x78\x01");
  ASSERT_TRUE(insn2.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn2.DebugString()),
            "add dword ptr [rsi+rax*4+0x78], 0x1");
  EXPECT_THAT(insn2.may_have_split_lock(regs), IsOkAndHolds(false));

  // RIP relative addressing. Check that RIP value is adjusted correctly.
  regs.rip = 0x1000;
  DecodedInsn insn3({"\x48\x87\x05\xf4\xff\xff\xff"});
  ASSERT_TRUE(insn3.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn3.DebugString()),
            "xchg qword ptr [rip-0xc], rax");
  EXPECT_THAT(insn3.may_have_split_lock(regs), IsOkAndHolds(true));

  // A bit test instruction uses both operands to determine the
  // actually memory address accessed.
  regs.r15 = 0x20000000;
  regs.rcx = 0xf5fd74df;
  DecodedInsn insn4("\xf3\x67\xf0\x4b\x0f\xb3\x4f\x67");
  ASSERT_TRUE(insn4.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn4.DebugString()),
            "xrelease lock btr qword ptr [r15d+0x67], rcx");
  EXPECT_THAT(insn4.may_have_split_lock(regs), IsOkAndHolds(true));
  regs.rcx += 64;
  EXPECT_THAT(insn4.may_have_split_lock(regs), IsOkAndHolds(false));

  // Bit test instruction with immediate bit offset.
  regs.rsi = 0xfff;
  DecodedInsn insn5("\x67\x66\xf0\x0f\xba\x2e\xf7");
  ASSERT_TRUE(insn5.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn5.DebugString()),
            "lock bts word ptr [esi], 0xf7");
  EXPECT_THAT(insn5.may_have_split_lock(regs), IsOkAndHolds(true));
  regs.rsi = 0xffe;
  EXPECT_THAT(insn5.may_have_split_lock(regs), IsOkAndHolds(false));

  // A compare-exchange instruction using a register-pair.
  regs.rsi = 0xfffc;
  DecodedInsn insn6("\xf0\x0f\xc7\x0e");
  ASSERT_TRUE(insn6.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn6.DebugString()),
            "lock cmpxchg8b qword ptr [rsi]");
  EXPECT_THAT(insn6.may_have_split_lock(regs), IsOkAndHolds(true));
}

TEST(DecodedInsn, ConstructWithAddress) {
  DecodedInsn insn("\x74\x02", 0x123000);
  ASSERT_TRUE(insn.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn.DebugString()), "jz 0x123004");
}

TEST(DecodedInsn, IsRepByteStore) {
  struct TestCase {
    const char* raw_bytes = nullptr;    // instruction bytes.
    const char* disassembly = nullptr;  // expected value for DebugString().
    bool is_rep_byte_store = false;  // expected value for is_rep_byte_store().
  };

  const std::vector<TestCase> test_cases = {
      {
          .raw_bytes = "\x67\xf3\xa4",
          .disassembly = "rep movsb byte ptr [edi], byte ptr [esi]",
          .is_rep_byte_store = true,
      },
      {
          .raw_bytes = "\xf3\x67\xaa",
          .disassembly = "rep stosb byte ptr [edi]",
          .is_rep_byte_store = true,
      },
      {
          // Without REP prefix
          .raw_bytes = "\x67\xa4",
          .disassembly = "movsb byte ptr [edi], byte ptr [esi]",
          .is_rep_byte_store = false,
      },
      {
          // Store size not byte
          .raw_bytes = "\x67\x66\xf3\xa5",
          .disassembly = "rep movsw word ptr [edi], word ptr [esi]",
          .is_rep_byte_store = false,
      },
      {
          // Not a rep store.
          .raw_bytes = "\x67\xf3\xae",
          .disassembly = "rep scasb byte ptr [edi]",
          .is_rep_byte_store = false,
      },
      {
          // Not a string operation.
          .raw_bytes = "\x90",
          .disassembly = "nop",
          .is_rep_byte_store = false,
      },
      {
          // I/O string operations are a separate category.
          .raw_bytes = "\x6e",
          .disassembly = "outsb",
          .is_rep_byte_store = false,
      },
  };

  for (const auto& test_case : test_cases) {
    DecodedInsn insn(test_case.raw_bytes);
    ASSERT_TRUE(insn.is_valid());
    EXPECT_EQ(absl::StripAsciiWhitespace(insn.DebugString()),
              test_case.disassembly);
    EXPECT_EQ(test_case.is_rep_byte_store, insn.is_rep_byte_store());
  }
}

TEST(DecodedInsn, may_access_region) {
  DecodedInsn insn("\xc5\x7c\x5a\x9a\xf2\xff\x5e\xff");
  ASSERT_TRUE(insn.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn.DebugString()),
            "vcvtps2pd ymm11, xmmword ptr [rdx-0xa1000e]");
  struct user_regs_struct regs{};
  regs.rdx = 0x10ff5;
  constexpr uintptr_t kVSyscallStart = 0xffffffffff600000ULL;
  constexpr uintptr_t kVSyscallSize = 0x800000;
  EXPECT_THAT(insn.may_access_region(regs, kVSyscallStart, kVSyscallSize),
              IsOkAndHolds(true));

  // Test error margin.
  const uintptr_t memory_operand_address = regs.rdx - 0xa1000eULL;
  const size_t error_margin = 64;
  EXPECT_THAT(
      insn.may_access_region(regs, memory_operand_address, 1, error_margin),
      IsOkAndHolds(true));
  EXPECT_THAT(insn.may_access_region(
                  regs, memory_operand_address - error_margin, 1, error_margin),
              IsOkAndHolds(true));
  EXPECT_THAT(
      insn.may_access_region(regs, memory_operand_address - error_margin - 1, 1,
                             error_margin),
      IsOkAndHolds(false));
  EXPECT_THAT(insn.may_access_region(
                  regs, memory_operand_address + error_margin, 1, error_margin),
              IsOkAndHolds(true));
  EXPECT_THAT(
      insn.may_access_region(regs, memory_operand_address + error_margin + 1, 1,
                             error_margin),
      IsOkAndHolds(false));

  // Test overflows are handled correctly.
  DecodedInsn insn2("\x48\x0f\xb6\x18");
  ASSERT_TRUE(insn2.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn2.DebugString()),
            "movzx rbx, byte ptr [rax]");
  regs.rax = 42;
  EXPECT_THAT(insn2.may_access_region(regs, 10, 11, 100), IsOkAndHolds(true));
  constexpr uintptr_t kAddressMax = std::numeric_limits<uintptr_t>::max();
  regs.rax = kAddressMax - 10;
  EXPECT_THAT(insn2.may_access_region(regs, kAddressMax - 1, kAddressMax, 100),
              IsOkAndHolds(true));

  // Test implicit memory operand.
  DecodedInsn insn3("\x50");
  ASSERT_TRUE(insn3.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn3.DebugString()), "push rax");
  regs.rsp = 0x12345678;

  // may_access_region() does not correctly take into account pre-decrement of
  // push but it is okay since the default margin of error is 64k.
  EXPECT_THAT(insn3.may_access_region(regs, regs.rsp, regs.rsp + 1),
              IsOkAndHolds(true));

  // Gather/Scatter instructions use vector registers as indices. For now,
  // may_access_region() always return true as we do not have vector register
  // contents in tracing.
  DecodedInsn insn4("\x62\xf2\xfd\x49\xa2\x0c\x07");
  ASSERT_TRUE(insn4.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn4.DebugString()),
            "vscatterdpd qword ptr [rdi+ymm0*1], k1, zmm1");
  regs.rdi = 0;
  EXPECT_THAT(insn4.may_access_region(regs, kVSyscallStart, kVSyscallSize),
              IsOkAndHolds(true));
}

TEST(DecodedInsn, may_access_memory) {
  DecodedInsn insn("\x90");
  ASSERT_TRUE(insn.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn.DebugString()), "nop");
  EXPECT_FALSE(insn.may_access_memory());

  DecodedInsn insn2("\xc6\x03\x01");
  ASSERT_TRUE(insn2.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn2.DebugString()),
            "mov byte ptr [rbx], 0x1");
  EXPECT_TRUE(insn2.may_access_memory());

  // Implicit memory operand.
  DecodedInsn insn3("\xc3");
  ASSERT_TRUE(insn3.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn3.DebugString()), "ret");
  EXPECT_TRUE(insn3.may_access_memory());
}

TEST(DecodedInsn, clzero) {
  DecodedInsn insn("\x0f\x01\xfc");
  ASSERT_TRUE(insn.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn.DebugString()), "clzero");
  EXPECT_TRUE(insn.is_allowed_in_runner());
}

TEST(DecodedInsn, clzero_with_prefix) {
  DecodedInsn insn("\xf2\x0f\x01\xfc");
  ASSERT_TRUE(insn.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn.DebugString()), "clzero");
  EXPECT_FALSE(insn.is_allowed_in_runner());
}

TEST(DecodedInsn, canonical_evex_sp) {
  struct TestCase {
    const char* raw_bytes = nullptr;    // instruction bytes.
    const char* disassembly = nullptr;  // expected value for DebugString().
    bool is_non_canonical_evex_sp =
        false;  // expected value for is_non_canonical_evex_sp().
  };

  const std::vector<TestCase> test_cases = {
      // Non-EVEX instruction.
      {
          .raw_bytes = "\x90",
          .disassembly = "nop",
          .is_non_canonical_evex_sp = false,
      },
      // SP not involved.
      {
          .raw_bytes = "\x62\x32\xfd\x48\x7c\xf8",
          .disassembly = "vpbroadcastq zmm15, rax",
          .is_non_canonical_evex_sp = false,
      },
      // SP is involved but not read.
      {
          .raw_bytes = "\x62\x31\xfd\x08\x7e\xec",
          .disassembly = "vmovq rsp, xmm13",
          .is_non_canonical_evex_sp = false,
      },
      // EVEX instructions, reading from SP and writing to AVX registers.
      {
          .raw_bytes = "\x62\x32\xfd\x48\x7c\xfc",
          .disassembly = "vpbroadcastq zmm15, rsp",
          .is_non_canonical_evex_sp = true,
      },
      {
          .raw_bytes = "\x62\x72\xfd\x48\x7c\xfc",
          .disassembly = "vpbroadcastq zmm15, rsp",
          .is_non_canonical_evex_sp = false,
      },
      {
          .raw_bytes = "\x62\xb1\xfd\x08\x6e\xcc",
          .disassembly = "vmovq xmm1, rsp",
          .is_non_canonical_evex_sp = true,
      },
      {
          .raw_bytes = "\x62\xf1\xfd\x08\x6e\xcc",
          .disassembly = "vmovq xmm1, rsp",
          .is_non_canonical_evex_sp = false,
      },
      {
          // Test that multiple 0x62 in the EVEX prefix can be properly handled.
          .raw_bytes = "\x62\x62\xfd\x48\x7c\xfc",
          .disassembly = "vpbroadcastq zmm31, rsp",
          .is_non_canonical_evex_sp = false,
      },
      {
          .raw_bytes = "\x62\x22\xfd\x48\x7c\xfc",
          .disassembly = "vpbroadcastq zmm31, rsp",
          .is_non_canonical_evex_sp = true,
      },
      {
          // With legacy prefix.
          .raw_bytes = "\x65\x62\x32\xfd\x48\x7c\xfc",
          .disassembly = "vpbroadcastq zmm15, rsp",
          .is_non_canonical_evex_sp = true,
      },
      // Read from other SP variants.
      {
          .raw_bytes = "\x62\x32\x7d\x28\x7c\xfc",
          .disassembly = "vpbroadcastd ymm15, esp",
          .is_non_canonical_evex_sp = true,
      },
      {
          .raw_bytes = "\x62\x32\x7d\x28\x7b\xfc",
          .disassembly = "vpbroadcastw ymm15, esp",
          .is_non_canonical_evex_sp = true,
      },
  };
  for (const auto& test_case : test_cases) {
    DecodedInsn insn(test_case.raw_bytes);
    ASSERT_TRUE(insn.is_valid());
    EXPECT_EQ(absl::StripAsciiWhitespace(insn.DebugString()),
              test_case.disassembly);
    EXPECT_EQ(test_case.is_non_canonical_evex_sp,
              insn.is_non_canonical_evex_sp());
  }
}

// Register-based vpalignr is fine.
TEST(DecodedInsn, vpalign_registers_allowed) {
  DecodedInsn insn("\x62\x83\x45\x05\x0f\xc8\xff");
  ASSERT_TRUE(insn.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn.DebugString()),
            "vpalignr xmm17{k5}, xmm23, xmm24, 0xff");
  EXPECT_TRUE(insn.is_allowed_in_runner());
}

// A vpalignr with memory operand _could_ trigger a GP fault if the address is
// non-canonical. This case can confuse the Linux kernel, resulting in it
// identifying it as a disallowed STR instruction and in some cases emulating it
// as if it were a STR instruction.
TEST(DecodedInsn, vpalign_memory_not_allowed) {
  DecodedInsn insn("\x62\x83\xc5\x05\x0f\x08\xff");
  ASSERT_TRUE(insn.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn.DebugString()),
            "vpalignr xmm17{k5}, xmm23, xmmword ptr [r8], 0xff");
  EXPECT_FALSE(insn.is_allowed_in_runner());
}

// Register-based palignr is fine.
TEST(DecodedInsn, palign_registers_allowed) {
  DecodedInsn insn("\x66\x0f\x3a\x0f\xdc\xff");
  ASSERT_TRUE(insn.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn.DebugString()),
            "palignr xmm3, xmm4, 0xff");
  EXPECT_TRUE(insn.is_allowed_in_runner());
}

// Memory-based palignr is suspect.
TEST(DecodedInsn, palign_memory_allowed) {
  DecodedInsn insn("\x66\x41\x0f\x3a\x0f\x18\xff");
  ASSERT_TRUE(insn.is_valid());
  EXPECT_EQ(absl::StripAsciiWhitespace(insn.DebugString()),
            "palignr xmm3, xmmword ptr [r8], 0xff");
  EXPECT_FALSE(insn.is_allowed_in_runner());
}

// This test covers a special case where the string `raw_bytes` that used by the
// DecodedInsn constructor is out of scope. In such case, calling xed's API
// xed_decoded_inst_get_byte() within the DecodedInsn instance will return junk
// data. This test ensures that the we can get the correct raw instruction
// bytes.
TEST(DecodedInsn, can_get_correct_raw_bytes) {
  DecodedInsn insn = [&]() {
    std::string raw_bytes = {0x62, 0x72, 0xfd, 0x48, 0x7c, 0xfc};
    return DecodedInsn(raw_bytes);
  }();

  ASSERT_TRUE(insn.is_valid());
  ASSERT_EQ(absl::StripAsciiWhitespace(insn.DebugString()),
            "vpbroadcastq zmm15, rsp");
  DecodedInsnTestPeer peer(insn);
  EXPECT_EQ(peer.get_raw_bytes(),
            std::string({0x62, 0x72, 0xfd, 0x48, 0x7c, 0xfc}));

  DecodedInsn moved = std::move(insn);
  DecodedInsnTestPeer moved_peer(moved);
  EXPECT_EQ(moved_peer.get_raw_bytes(),
            std::string({0x62, 0x72, 0xfd, 0x48, 0x7c, 0xfc}));
}

}  // namespace
}  // namespace silifuzz
