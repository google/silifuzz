# Copyright 2026 The SiliFuzz Authors.
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

"""Foundational instruction library for SiliFuzz minimization.

Introduces core data structures (Insn), NOP generation, byte escaping, and log
parsing for x86_64 and AArch64 architectures.
"""

from collections.abc import Iterable, Mapping
import dataclasses
import types

from proto import snapshot_pb2

_SINGLE_NOP_INSTRUCTIONS_BY_SIZE: Mapping[
    snapshot_pb2.Snapshot.Architecture, Mapping[int, bytes]
] = types.MappingProxyType({
    snapshot_pb2.Snapshot.X86_64: {
        # The following 9 NOPs are recommended by Intel in their Optimization
        # Guide.
        1: b"\x90",
        2: b"\x66\x90",
        3: b"\x0f\x1f\x00",
        4: b"\x0f\x1f\x40\x00",
        5: b"\x0f\x1f\x44\x00\x00",
        6: b"\x66\x0f\x1f\x44\x00\x00",
        7: b"\x0f\x1f\x80\x00\x00\x00\x00",
        8: b"\x0f\x1f\x84\x00\x00\x00\x00\x00",
        9: b"\x66\x0f\x1f\x84\x00\x00\x00\x00\x00",
        # Not recommended by Intel, but is effectively a NOP.
        10: b"\x66\x66\x0f\x1f\x84\x00\x00\x00\x00\x00",
        11: b"\x66\x66\x66\x0f\x1f\x84\x00\x00\x00\x00\x00",
    },
    snapshot_pb2.Snapshot.AARCH64: {
        4: b"\x1f\x20\x03\xd5",
    },
})

# Maximum length of a single NOP instruction in bytes for each architecture.
MAX_NOP_LEN_BY_ARCH: Mapping[snapshot_pb2.Snapshot.Architecture, int] = (
    types.MappingProxyType({
        arch: max(nop_by_len.keys())
        for arch, nop_by_len in _SINGLE_NOP_INSTRUCTIONS_BY_SIZE.items()
    })
)

# Minimum length of a single NOP instruction in bytes for each architecture.
MIN_NOP_LEN_BY_ARCH: Mapping[snapshot_pb2.Snapshot.Architecture, int] = (
    types.MappingProxyType({
        arch: min(nop_by_len.keys())
        for arch, nop_by_len in _SINGLE_NOP_INSTRUCTIONS_BY_SIZE.items()
    })
)


@dataclasses.dataclass(frozen=True)
class Insn:
  """A single disassembled instruction from a snapshot trace.

  Attributes:
    addr: The address of the instruction in memory.
    len: The length of the instruction in bytes.
    repr: The mnemonic representation of the instruction.
  """

  addr: int
  len: int
  repr: str

  def __repr__(self) -> str:
    return f"Insn(addr={self.addr:#x}, len={self.len}, repr={self.repr!r})"

  def is_nop(self) -> bool:
    """Determines if the instruction is a NOP variant.

    Note on feni8087_nop:
    In x86/x87 floating-point instructions, feni8087_nop acts as an x87 FPU
    coprocessor NOP. However, unlike standard integer NOPs (0x90), x87 FPU NOPs
    interact with the x87 status/tag word registers and can raise pending
    floating-point unmasked exceptions. Therefore, treating feni8087_nop as a
    harmless replaceable NOP can break snapshot determinism or alter exception
    behavior. We explicitly exclude it.

    Returns:
      True if the instruction is a NOP variant, False otherwise.
    """
    return "nop" in self.repr and ("feni8087_nop" not in self.repr)

  def is_simple_nop(self, arch: snapshot_pb2.Snapshot.Architecture) -> bool:
    """Determines if the instruction is a simple NOP for the given architecture.

    Note on x86_64 len == 1:
    x86_64 has multi-byte NOP variants (e.g., 0x0f 0x1f ...). This check
    isolates canonical simple 1-byte NOPs (0x90).

    Args:
      arch: The SiliFuzz Snapshot Architecture enum.

    Returns:
      True if the instruction is a simple NOP for the given architecture,
      False otherwise.
    """
    if arch == snapshot_pb2.Snapshot.AARCH64:
      return self.is_nop()
    return self.len == 1 and self.is_nop()


@dataclasses.dataclass
class NopSequence:
  """A contiguous sequence of NOP instructions.

  Attributes:
    addr: The address of the first NOP instruction in the sequence.
    len: The length of the NOP sequence in bytes.
  """

  addr: int
  len: int

  def __repr__(self) -> str:
    return f"NopSequence(addr={self.addr:#x}, len={self.len})"


def nop_sequence_bytes(
    arch: snapshot_pb2.Snapshot.Architecture, length: int
) -> bytes:
  """Generates a sequence of NOP instructions of the specified byte length for the given architecture.

  Args:
    arch: The SiliFuzz Snapshot Architecture enum.
    length: The required byte length.

  Returns:
    The NOP sequence bytes.

  Raises:
    ValueError: If length is invalid or architecture is unsupported.
  """
  if length < 0:
    raise ValueError("Length must be non-negative.")
  if arch not in _SINGLE_NOP_INSTRUCTIONS_BY_SIZE:
    raise ValueError(f"Unsupported architecture for NOP generation: {arch}")
  if arch == snapshot_pb2.Snapshot.X86_64:
    return _SINGLE_NOP_INSTRUCTIONS_BY_SIZE[arch][1] * length
  elif arch == snapshot_pb2.Snapshot.AARCH64:
    if length % 4 != 0:
      raise ValueError(
          f"AArch64 NOP length must be a multiple of 4, got {length}."
      )
    return _SINGLE_NOP_INSTRUCTIONS_BY_SIZE[arch][4] * (length // 4)
  raise ValueError(f"Unsupported architecture for NOP generation: {arch}")


def single_nop_bytes(
    arch: snapshot_pb2.Snapshot.Architecture, length: int
) -> bytes:
  """Generates a single NOP instruction of the specified byte length for the given architecture.

  A single NOP instruction will always be one opcode entity, despite potentially
  consisting of multiple bytes.

  Args:
    arch: The SiliFuzz Snapshot Architecture enum.
    length: The required byte length.

  Returns:
    The single NOP instruction bytes.

  Raises:
    ValueError: If length is invalid or architecture is unsupported.
  """
  if arch not in _SINGLE_NOP_INSTRUCTIONS_BY_SIZE:
    raise ValueError(f"Unsupported architecture for NOP generation: {arch}")
  arch_table = _SINGLE_NOP_INSTRUCTIONS_BY_SIZE[arch]
  if length not in arch_table:
    raise ValueError(
        f"No single NOP instruction of size {length} for architecture "
        f"{snapshot_pb2.Snapshot.Architecture.Name(arch)}."
    )
  return arch_table[length]


def _parse_trace_lines(
    lines: Iterable[str], *, fixed_size: int | None = None
) -> list[Insn]:
  """Parses snap_tool trace output lines into Insn objects.

  Deduplicates identical instructions at the same address.

  Args:
    lines: Raw text lines from snap_tool trace.
    fixed_size: Fixed instruction byte size if applicable (e.g., 4 for AArch64),
      or None to parse size dynamically from 'size=' attribute (e.g., for x86).

  Returns:
    List of parsed Insn objects.
  """
  insns: list[Insn] = []
  seen: set[Insn] = set()
  target_splits = 3 if fixed_size is None else 2

  # Expected line formats:
  #   - variable size: <offset> addr=<addr> size=<size> <mnemonic>
  #   - fixed size: <offset> addr=<addr> <mnemonic>
  for line in lines:
    line = line.strip()
    if "addr=" not in line:
      continue
    if fixed_size is None and "size=" not in line:
      continue

    parts = line.split(" ", maxsplit=target_splits)[1:]
    if len(parts) < target_splits:
      continue

    try:
      if fixed_size is not None:
        addr_str, mnemonic = parts
        size = fixed_size
      else:
        addr_str, size_str, mnemonic = parts
        size = int(size_str.removeprefix("size="), base=10)

      addr = int(addr_str.removeprefix("addr="), base=16)
      candidate = Insn(addr=addr, len=size, repr=mnemonic)
      if candidate not in seen:
        seen.add(candidate)
        insns.append(candidate)
    except ValueError:
      continue

  return insns


def parse_trace(
    lines: list[str], arch: snapshot_pb2.Snapshot.Architecture
) -> list[Insn]:
  """Parses snap_tool trace output lines into Insn objects for the given architecture.

  Deduplicates identical instructions at the same address.

  Args:
    lines: Raw text lines from snap_tool trace.
    arch: The SiliFuzz Snapshot Architecture enum.

  Returns:
    List of parsed Insn objects.

  Raises:
    ValueError: If the architecture is unsupported.
  """
  if arch == snapshot_pb2.Snapshot.X86_64:
    return _parse_trace_lines(lines, fixed_size=None)
  elif arch == snapshot_pb2.Snapshot.AARCH64:
    return _parse_trace_lines(lines, fixed_size=4)
  else:
    raise ValueError(f"Unsupported architecture for trace parsing: {arch}")
