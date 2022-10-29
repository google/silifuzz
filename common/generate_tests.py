#!/usr/bin/env python3

# Copyright 2022 The SiliFuzz Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
r"""A self-contained script that generates source code.

The generated source code describes how to build Snapshots that will be used for
testing.

If you are running on x86_64, you may need to install GCC for AArch64.
sudo apt-get -y install gcc-aarch64-linux-gnu

To run:
./third_party/silifuzz/common/generate_tests.py > \
third_party/silifuzz/common/snapshot_test_config.cc && hg fix
"""

import argparse
import dataclasses
import json
import os.path
import subprocess
import sys
import tempfile

# These values should match Snapshot::Architecture in snapshot.proto
X86_64 = 1
AARCH64 = 2

# Page number (i.e. address / page size) at the beginning of memory region
# used by test snapshots.
TEST_SNAPSHOTS_REGION_BASE = 0x12345

# The spacing between each test snapshot. Each test snapshot will fit its code
# and data in MAX_PAGES_PER_TEST page memory range.
# In practice, each test snapshot uses 2 pages of memory so this means there
# is some dead space between each test, but this isn't a problem.
MAX_PAGES_PER_TEST = 16

PAGE_SIZE = 4096


def test_snapshot_code_addr(index):
  return (TEST_SNAPSHOTS_REGION_BASE + index * MAX_PAGES_PER_TEST) * PAGE_SIZE


def src_to_instructions(src, temp_dir, bin_filename):
  clang_target_str = "x86_64-none-eabi"

  # Create the source file
  src_filename = os.path.join(temp_dir, "example.S")
  with open(src_filename, "w") as sf:
    src = src.rstrip()
    sf.write(src)

  obj_filename = os.path.join(temp_dir, "example.o")

  # Compile
  subprocess.check_call([
      "clang", "-target", clang_target_str, "-c", src_filename, "-o",
      obj_filename
  ])

  # Extract the compiled instructions
  subprocess.check_call(["objcopy", "-O", "binary", obj_filename, bin_filename])


def disassemble(bin_filename, code_addr):
  objdump_arch_str = "i386:x86-64"

  if os.path.getsize(bin_filename) > 0:
    # Objdump the compiled instructions
    disam = subprocess.check_output([
        "objdump", "-m", objdump_arch_str, "-D", "-b", "binary",
        f"--adjust-vma={hex(code_addr)}", bin_filename
    ]).decode("utf8")
    disam = disam.rstrip()
    # Trim off the preamble
    disam = "\n".join(disam.splitlines()[7:])
  else:
    # Objdump can't handle an empty input, so fake it
    disam = f"{code_addr:12x}:\t<empty>"

  # objdump outputs tabs
  disam = disam.expandtabs(8)

  return disam


@dataclasses.dataclass
class TestSnapshot:

  index: int
  name: str
  arch: int
  normal_end: bool
  stack_bytes_used: int
  code_addr: int
  code_num_bytes: int
  data_addr: int
  data_num_bytes: int
  instruction_bytes: bytes
  disassembly: str


class Builder:

  def __init__(self):
    self.index = 0
    self.snapshots = []

  # Build a single test snapshot
  def snapshot(self,
               name,
               arch,
               normal_end=True,
               stack_bytes_used=0,
               src=None,
               raw_bytes=None):
    with tempfile.TemporaryDirectory() as temp_dir:
      bin_filename = os.path.join(temp_dir, "example.bin")

      code_addr = test_snapshot_code_addr(self.index)

      if src is not None:
        src_to_instructions(src, temp_dir, bin_filename)
      elif raw_bytes is not None:
        # Directly specify the compiled instructions
        with open(bin_filename, "wb") as bf:
          bf.write(bytes(raw_bytes))
      else:
        raise Exception("Must specify src or raw_bytes")

      disassembly = disassemble(bin_filename, code_addr)

      with open(bin_filename, "rb") as bf:
        instruction_bytes = bf.read()

      self.snapshots.append(
          TestSnapshot(
              index=self.index,
              name=name,
              arch=arch,
              normal_end=normal_end,
              stack_bytes_used=stack_bytes_used,
              code_addr=code_addr,
              code_num_bytes=PAGE_SIZE,
              data_addr=code_addr + PAGE_SIZE,
              data_num_bytes=PAGE_SIZE,
              instruction_bytes=instruction_bytes,
              disassembly=disassembly,
          ))

      self.index += 1


def build_test_snapshots(b):
  b.snapshot(name="Empty", arch=X86_64, normal_end=True, src="")

  b.snapshot(
      name="EndsAsExpected", arch=X86_64, normal_end=True, src="""
nop
""")

  b.snapshot(name="HasPlatformMismatch", arch=X86_64, src="""
nop
""")

  b.snapshot(
      name="EndsUnexpectedly",
      arch=X86_64,
      normal_end=False,
      src="""
// The endpoint generated below has address that is after the last
// instruction byte of `bytecode`. By making code be the trap instruction,
// we guarantee that the actual endpoint instruction address will not
// match the expected one.
//
// Currently this is the same `bytecode` as for kINT3 below because of
// how we implement endpoint detection. However, the intentions
// behind kINT3 and kEndsUnexpectedly are different.
int3
""")

  b.snapshot(
      name="RegsMismatch",
      arch=X86_64,
      src="""
// rsp has non-0 bits so, this modifies rax
xor %rsp, %rax
""")

  b.snapshot(
      name="MemoryMismatch",
      arch=X86_64,
      stack_bytes_used=8 * 3,
      src="""
// save flags
pushfq
push %rax

// make RAX -1
xor %rax, %rax
not %rax

// put non-0 RAX into stack thus mutating
// the 0-initialized memory.
push %rax
pop %rax

// restore registers and flags
pop %rax
popfq
""")

  b.snapshot(
      name="RegsAndMemoryMismatch",
      arch=X86_64,
      stack_bytes_used=8,
      src="""
// deterministically mutate regs and memory
xor %rsp, %rbx
xor %rax, %rax
not %rax
push %rax
""")

  b.snapshot(
      name="RegsMismatchRandom",
      arch=X86_64,
      src="""
// The snapshot looks at CPUID (non-deterministic but stable) and then
// runs RDRAND %RAX if supported else RDTSC. This ensures this snapshot
// produces a random value in %EAX under Unicorn (does not support
// RDRAND), on all production platforms and under seccomp(2) which
// disables RDTSC(P) via CR4.TSD.
movq $0x1, %rax
cpuid
// Check RDRAND bit (CPUID.01H:ECX.RDRAND[bit 30]).
andl $(1 << 30), %ecx
jz 1f
rdrand %rax
jmp 2f
1: rdtsc
2:
""")

  b.snapshot(
      name="MemoryMismatchRandom",
      arch=X86_64,
      stack_bytes_used=8 * 4,
      src="""
// save flags and registers
pushfq
push %rax
push %rdx

// place a random number in edx:eax
rdtsc

// put the random value onto stack  thus guaranteeing
// there's a random value on the stack that can never
// be matched by any expected memory state.
push %rax

// restore registers and flags
pop %rax
pop %rdx
pop %rax
popfq
""")

  b.snapshot(
      name="RegsAndMemoryMismatchRandom",
      arch=X86_64,
      stack_bytes_used=8,
      src="""
// place a random number in EAX:EDX and stack
rdtsc
push %rax
""")

  b.snapshot(name="ICEBP", arch=X86_64, normal_end=False, raw_bytes=[0xf1])

  # Note that this is the same `bytecode` as snapshot.trap_instruction().
  b.snapshot(name="INT3", arch=X86_64, normal_end=False, raw_bytes=[0xcc])

  b.snapshot(
      name="INT3_CD03", arch=X86_64, normal_end=False, raw_bytes=[0xcd, 0x03])

  b.snapshot(name="SigIll", arch=X86_64, normal_end=False, src="""
ud2
""")

  b.snapshot(
      name="SigSegvWrite",
      arch=X86_64,
      normal_end=False,
      src="""
movq 8(%rbp), %rax
mov %rbx, 0(%rax)
""")

  b.snapshot(
      name="SigSegvRead",
      arch=X86_64,
      normal_end=False,
      src="""
movq 0(%rbp), %rax
mov 0(%rax), %rbx
""")

  b.snapshot(
      name="SigSegvExec",
      arch=X86_64,
      normal_end=False,
      src="""
movq 16(%rbp), %rax
jmp *%rax
""")

  b.snapshot(
      name="Syscall",
      arch=X86_64,
      src="""
xor %rsi, %rsi
xor %rdi, %rdi
// 0x135 == 309 == SYS_getcpu
mov $0x135, %rax
syscall

// erases any result whatever it may be so that
// the snapshot always ends deterministically
xor %rax, %rax
""")

  b.snapshot(
      name="GeneralProtectionFault",
      arch=X86_64,
      normal_end=False,
      src="""
fxsave 1(%rip)
""")

  b.snapshot(
      name="ChangesSegmentReg",
      arch=X86_64,
      src="""
// The 0x3 value matters here. There choice
// of possible values is limited by LDT/GDT.
// Values <= 3 are always fair game according
// to the ISA though.
// CS can only be loaded with a RET. SS is
// very special wrt checks performed by the CPU
movw $0x3, %ax
movw %ax, %es
movw %ax, %ds
movw %ax, %gs
movw %ax, %fs
""")

  b.snapshot(name="In", arch=X86_64, normal_end=False, src="""
in %dx, %eax
""")

  b.snapshot(
      name="Runaway",
      arch=X86_64,
      normal_end=False,
      src="""
// A trivial infinite loop (can only have one end-point rip value when
// interrupted):
jmp .
""")

  b.snapshot(
      name="Splitlock",
      arch=X86_64,
      src="""
// x86 L1 cache line size is 64b typically. Just in
// case future CPUs have wider cache lines, align down
// to 256b boundary from stack top.
movq %rsp, %rax
dec %rax
xorb %al,%al
lock incl -1(%rax)
""")


def generate_source(b, out):
  out.write(f"""\
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

#include "third_party/silifuzz/common/snapshot_test_config.h"

#include "third_party/silifuzz/util/checks.h"

namespace silifuzz {{
namespace {{

// This file is generated by generate_tests.py. Do not edit this file by hand.

const TestSnapshotConfig configs[{len(b.snapshots)}] = {{
""")

  for s in b.snapshots:
    # Note: using json.dumps to get a double-quoted string.
    out.write(f"""\
    {{
        .name = {json.dumps("k" + s.name)},
        .code_addr = {hex(s.code_addr)},
        .code_num_bytes = {hex(s.code_num_bytes)},
        .data_addr = {hex(s.data_addr)},
        .data_num_bytes = {hex(s.data_num_bytes)},
""")

    for line in s.disassembly.splitlines():
      out.write(f"        // {line}\n")

    byte_list = ", ".join([hex(byte) for byte in s.instruction_bytes])
    out.write(f"""\
        .instruction_bytes = {{{byte_list}}},
        .normal_end = {repr(bool(s.normal_end)).lower()},
        .stack_bytes_used = {s.stack_bytes_used},
    }},
""")

  out.write("""};

}  // namespace

const TestSnapshotConfig& GetTestSnapshotConfig(TestSnapshots::Type type) {
  CHECK_LT(type, sizeof(configs) / sizeof(TestSnapshotConfig));
  return configs[type];
}

}  // namespace silifuzz
""")


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument("--test", action="store_true")
  args = parser.parse_args()

  b = Builder()
  # If this is a test, mock the functionality we can't run in CI.
  if not args.test:
    build_test_snapshots(b)
  else:
    index = 0
    code_addr = test_snapshot_code_addr(index)
    b.snapshots.append(
        TestSnapshot(
            index=0,
            name="Test",
            arch=X86_64,
            normal_end=True,
            stack_bytes_used=0,
            code_addr=code_addr,
            code_num_bytes=PAGE_SIZE,
            data_addr=code_addr + PAGE_SIZE,
            data_num_bytes=PAGE_SIZE,
            instruction_bytes=bytes([1, 2, 3, 4]),
            disassembly="Mock disassembly",
        ))
  generate_source(b, sys.stdout)


if __name__ == "__main__":
  main()
