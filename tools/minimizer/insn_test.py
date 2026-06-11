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

from absl.testing import absltest
from absl.testing import parameterized

from proto import snapshot_pb2
from tools.minimizer import insn


class InsnTest(parameterized.TestCase):

  def test_insn_str(self) -> None:
    i = insn.Insn(addr=0x1000, len=3, repr="feni8087_nop")
    self.assertEqual(str(i), "Insn(addr=0x1000, len=3, repr='feni8087_nop')")

  @parameterized.named_parameters(
      dict(
          testcase_name="nop",
          single_insn=insn.Insn(addr=0x1000, len=1, repr="nop"),
          expected=True,
      ),
      dict(
          testcase_name="multi_byte_nop",
          single_insn=insn.Insn(addr=0x1000, len=4, repr="nop"),
          expected=True,
      ),
      dict(
          testcase_name="feni8087_nop",
          single_insn=insn.Insn(addr=0x1000, len=3, repr="feni8087_nop"),
          expected=False,
      ),
  )
  def test_is_nop(self, single_insn: insn.Insn, expected: bool) -> None:
    self.assertEqual(single_insn.is_nop(), expected)

  @parameterized.named_parameters(
      dict(
          testcase_name="x86_64_1_byte_nop",
          arch=snapshot_pb2.Snapshot.X86_64,
          single_insn=insn.Insn(addr=0x1000, len=1, repr="nop"),
          expected=True,
      ),
      dict(
          testcase_name="x86_64_3byte_nop",
          arch=snapshot_pb2.Snapshot.X86_64,
          single_insn=insn.Insn(addr=0x1000, len=3, repr="nop"),
          expected=False,
      ),
      dict(
          testcase_name="aarch64_4_byte_nop",
          arch=snapshot_pb2.Snapshot.AARCH64,
          single_insn=insn.Insn(addr=0x1000, len=4, repr="nop"),
          expected=True,
      ),
  )
  def test_is_simple_nop(
      self,
      arch: snapshot_pb2.Snapshot.Architecture,
      single_insn: insn.Insn,
      expected: bool,
  ) -> None:
    self.assertEqual(single_insn.is_simple_nop(arch), expected)

  def test_nop_sequence_repr(self) -> None:
    run = insn.NopSequence(addr=0x2000, len=5)
    self.assertEqual(repr(run), "NopSequence(addr=0x2000, len=5)")

  @parameterized.named_parameters(
      dict(
          testcase_name="x86_64",
          arch=snapshot_pb2.Snapshot.X86_64,
          length=3,
          expected=b"\x90\x90\x90",
      ),
      dict(
          testcase_name="x86_64_zero_length",
          arch=snapshot_pb2.Snapshot.X86_64,
          length=0,
          expected=b"",
      ),
      dict(
          testcase_name="aarch64",
          arch=snapshot_pb2.Snapshot.AARCH64,
          length=8,
          expected=b"\x1f\x20\x03\xd5\x1f\x20\x03\xd5",
      ),
      dict(
          testcase_name="aarch64_zero_length",
          arch=snapshot_pb2.Snapshot.AARCH64,
          length=0,
          expected=b"",
      ),
  )
  def test_nop_sequence_bytes(
      self,
      arch: snapshot_pb2.Snapshot.Architecture,
      length: int,
      expected: bytes,
  ) -> None:
    self.assertEqual(insn.nop_sequence_bytes(arch, length), expected)

  @parameterized.named_parameters(
      dict(
          testcase_name="negative_length",
          arch=snapshot_pb2.Snapshot.X86_64,
          length=-1,
          expected_error="non-negative",
      ),
      dict(
          testcase_name="aarch64_odd_length",
          arch=snapshot_pb2.Snapshot.AARCH64,
          length=3,
          expected_error="multiple of 4",
      ),
      dict(
          testcase_name="unsupported_architecture",
          arch=snapshot_pb2.Snapshot.UNDEFINED_ARCH,
          length=4,
          expected_error="Unsupported architecture",
      ),
  )
  def test_nop_sequence_bytes_invalid(
      self,
      arch: snapshot_pb2.Snapshot.Architecture,
      length: int,
      expected_error: str,
  ) -> None:
    with self.assertRaisesRegex(ValueError, expected_error):
      insn.nop_sequence_bytes(arch, length)

  @parameterized.named_parameters(
      dict(
          testcase_name="x86_64_1_byte",
          arch=snapshot_pb2.Snapshot.X86_64,
          length=1,
          expected=b"\x90",
      ),
      dict(
          testcase_name="x86_64_5_bytes",
          arch=snapshot_pb2.Snapshot.X86_64,
          length=5,
          expected=b"\x0f\x1f\x44\x00\x00",
      ),
      dict(
          testcase_name="x86_64_11_bytes",
          arch=snapshot_pb2.Snapshot.X86_64,
          length=11,
          expected=b"\x66\x66\x66\x0f\x1f\x84\x00\x00\x00\x00\x00",
      ),
      dict(
          testcase_name="aarch64",
          arch=snapshot_pb2.Snapshot.AARCH64,
          length=4,
          expected=b"\x1f\x20\x03\xd5",
      ),
  )
  def test_single_nop_bytes(
      self,
      arch: snapshot_pb2.Snapshot.Architecture,
      length: int,
      expected: bytes,
  ) -> None:
    self.assertEqual(insn.single_nop_bytes(arch, length), expected)

  @parameterized.named_parameters(
      dict(
          testcase_name="x86_64_zero_length",
          arch=snapshot_pb2.Snapshot.X86_64,
          length=0,
          expected_error="No single NOP instruction",
      ),
      dict(
          testcase_name="x86_64_12_byte",
          arch=snapshot_pb2.Snapshot.X86_64,
          length=12,
          expected_error="No single NOP instruction",
      ),
      dict(
          testcase_name="aarch64_5_byte",
          arch=snapshot_pb2.Snapshot.AARCH64,
          length=5,
          expected_error="No single NOP instruction",
      ),
      dict(
          testcase_name="unsupported_architecture",
          arch=snapshot_pb2.Snapshot.UNDEFINED_ARCH,
          length=4,
          expected_error="Unsupported architecture",
      ),
  )
  def test_single_nop_bytes_invalid(
      self,
      arch: snapshot_pb2.Snapshot.Architecture,
      length: int,
      expected_error: str,
  ) -> None:
    with self.assertRaisesRegex(ValueError, expected_error):
      insn.single_nop_bytes(arch, length)

  @parameterized.named_parameters(
      dict(
          testcase_name="x86_64",
          arch=snapshot_pb2.Snapshot.X86_64,
          lines=[
              "0x7f123 addr=0x1000 size=1 nop",
              "0x7f124 addr=0x1001 size=2 mov eax, 1",
              "0x7f125 addr=0x1000 size=1 nop",  # duplicate, should be deduped
              "invalid line without addr and size",
          ],
          expected=[
              insn.Insn(addr=0x1000, len=1, repr="nop"),
              insn.Insn(addr=0x1001, len=2, repr="mov eax, 1"),
          ],
      ),
      dict(
          testcase_name="aarch64",
          arch=snapshot_pb2.Snapshot.AARCH64,
          lines=[
              "1 addr=0x1000 nop",
              "2 addr=0x1004 add x0, x1, x2",
              "3 addr=0x1000 nop",  # duplicate, should be deduped
              "invalid line without addr",
          ],
          expected=[
              insn.Insn(addr=0x1000, len=4, repr="nop"),
              insn.Insn(addr=0x1004, len=4, repr="add x0, x1, x2"),
          ],
      ),
  )
  def test_parse_trace(
      self,
      arch: snapshot_pb2.Snapshot.Architecture,
      lines: list[str],
      expected: list[insn.Insn],
  ) -> None:
    insn_list = insn.parse_trace(lines, arch)
    self.assertEqual(insn_list, expected)


if __name__ == "__main__":
  absltest.main()
