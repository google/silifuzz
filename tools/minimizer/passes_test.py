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

from collections.abc import Callable, Iterable, Mapping, Sequence
import itertools
import random
from typing import Any, override
from unittest import mock

from absl.testing import absltest
from absl.testing import parameterized

from proto import snapshot_pb2
from tools.minimizer import engine
from tools.minimizer import insn
from tools.minimizer import passes
from tools.minimizer import schedule_pb2


class FakeDifferentialEngine(engine.DifferentialEngine):
  """Fake DifferentialEngine for hermetically testing pass algorithms."""

  def __init__(
      self,
      initial_snapshot: snapshot_pb2.Snapshot,
      trace_rounds: Iterable[list[str]],
      repro_results: Iterable[bool] | None = None,
  ) -> None:
    """Initializes the FakeDifferentialEngine.

    Args:
      initial_snapshot: The initial snapshot to minimize.
      trace_rounds: An iterable of trace line lists to return across sequential
        calls to trace().
      repro_results: An iterable of booleans representing the results of SDC
        repro. If None, all repro will succeed.
    """
    super().__init__(
        snapshot=initial_snapshot,
        good_cpu=0,
        bad_cpu=1,
        tool_executor=mock.create_autospec(
            engine.ToolExecutor, spec_set=True, instance=True
        ),
    )
    self._trace_rounds = iter(trace_rounds)
    self._repro_results = (
        iter(repro_results)
        if repro_results is not None
        else itertools.repeat(True)
    )
    self._next_snap_id = 1
    self._pc_by_snap_id: dict[str, int] = {}

  @override
  def trace(self) -> list[str]:
    try:
      return next(self._trace_rounds)
    except StopIteration:
      return []

  @override
  def set_pc(self, snapshot: snapshot_pb2.Snapshot, pc: int) -> bool:
    self._pc_by_snap_id[snapshot.id] = pc
    return True

  def get_pc(self, snapshot: snapshot_pb2.Snapshot) -> int | None:
    """Returns the simulated PC address set for the given snapshot."""
    return self._pc_by_snap_id.get(snapshot.id)

  @override
  def try_modify(
      self, mutation_fn: Callable[[snapshot_pb2.Snapshot], bool]
  ) -> bool:
    candidate = self.export_snapshot()
    candidate.id = f"snap_{self._next_snap_id}"
    self._next_snap_id += 1
    if not mutation_fn(candidate):
      return False
    if not next(self._repro_results):
      return False
    # As a test double subclass, updating active_snapshot should be okay.
    self._active_snapshot = candidate
    return True


class PassesTest(parameterized.TestCase):

  def setUp(self) -> None:
    super().setUp()
    self.mock_host = self.enter_context(
        mock.patch.object(engine, "host_platform", autospec=True)
    )

  def test_passes_registry(self) -> None:
    self.assertSameElements(
        passes.PassKind,
        passes.PASS_FN_BY_KIND.keys(),
    )

  def test_default_schedules(self) -> None:
    self.assertNotEmpty(
        passes.DEFAULT_PASSES_BY_ARCH[snapshot_pb2.Snapshot.X86_64]
    )
    self.assertNotEmpty(
        passes.DEFAULT_PASSES_BY_ARCH[snapshot_pb2.Snapshot.AARCH64]
    )

  @parameterized.named_parameters(
      dict(
          testcase_name="nop_pass_x86_64_success",
          pass_fn=passes.nop_pass,
          arch=snapshot_pb2.Snapshot.X86_64,
          initial_bytes=b"\xb8\x01\x00\x00\x00\xc3",
          trace_rounds=[
              ["1 addr=0x1000 size=5 mov eax, 1", "2 addr=0x1005 size=1 ret"],
          ],
          expected_bytes=b"\x90\x90\x90\x90\x90\xc3",
          expected_success=True,
          repro_results=[True],
      ),
      dict(
          testcase_name="nop_pass_x86_64_fail",
          pass_fn=passes.nop_pass,
          arch=snapshot_pb2.Snapshot.X86_64,
          initial_bytes=b"\xb8\x01\x00\x00\x00\xc3",
          trace_rounds=[
              ["1 addr=0x1000 size=5 mov eax, 1"],
          ],
          expected_bytes=b"\xb8\x01\x00\x00\x00\xc3",
          expected_success=False,
          repro_results=[False],
      ),
      dict(
          testcase_name="nop_pass_x86_64_partial_success",
          pass_fn=passes.nop_pass,
          arch=snapshot_pb2.Snapshot.X86_64,
          initial_bytes=b"\xb8\x01\x00\x00\x00\x83\xc3\x02\xc3",
          trace_rounds=[
              [
                  "1 addr=0x1000 size=5 mov eax, 1",
                  "2 addr=0x1005 size=3 add ebx, 2",
                  "3 addr=0x1008 size=1 ret",
              ],
          ],
          expected_bytes=b"\xb8\x01\x00\x00\x00\x90\x90\x90\xc3",
          expected_success=True,
          repro_results=[False, True],
      ),
      dict(
          testcase_name="nop_pass_aarch64_success",
          pass_fn=passes.nop_pass,
          arch=snapshot_pb2.Snapshot.AARCH64,
          initial_bytes=b"\x20\x00\x80\xd2\xc0\x03\x5f\xd6",
          trace_rounds=[
              ["1 addr=0x1000 mov x0, 1", "2 addr=0x1004 ret"],
          ],
          expected_bytes=b"\x1f\x20\x03\xd5\xc0\x03\x5f\xd6",
          expected_success=True,
          repro_results=[True],
      ),
      dict(
          testcase_name="fuse_pass_x86_64_success",
          pass_fn=passes.fuse_pass,
          arch=snapshot_pb2.Snapshot.X86_64,
          initial_bytes=b"\x90\x90\x90\xc3",
          trace_rounds=[
              [
                  "1 addr=0x1000 size=1 nop",
                  "2 addr=0x1001 size=1 nop",
                  "3 addr=0x1002 size=1 nop",
                  "4 addr=0x1003 size=1 ret",
              ],
          ],
          expected_bytes=b"\x0f\x1f\x00\xc3",
          expected_success=True,
          repro_results=[True],
      ),
      dict(
          testcase_name="fuse_pass_x86_64_partial_success",
          pass_fn=passes.fuse_pass,
          arch=snapshot_pb2.Snapshot.X86_64,
          initial_bytes=b"\x90\x90\x90\xc3",
          trace_rounds=[
              [
                  "1 addr=0x1000 size=1 nop",
                  "2 addr=0x1001 size=1 nop",
                  "3 addr=0x1002 size=1 nop",
                  "4 addr=0x1003 size=1 ret",
              ],
          ],
          expected_bytes=b"\x66\x90\x90\xc3",
          expected_success=True,
          repro_results=[False, True],
      ),
      dict(
          testcase_name="fuse_pass_x86_64_fail_multi_byte_nop",
          pass_fn=passes.fuse_pass,
          arch=snapshot_pb2.Snapshot.X86_64,
          initial_bytes=b"\x90\x66\x90\x90\xc3",
          trace_rounds=[
              [
                  "1 addr=0x1000 size=1 nop",
                  "2 addr=0x1001 size=2 nop",
                  "3 addr=0x1003 size=1 nop",
                  "4 addr=0x1004 size=1 ret",
              ],
          ],
          expected_bytes=b"\x90\x66\x90\x90\xc3",
          expected_success=False,
          repro_results=[],
      ),
      dict(
          testcase_name="fuse_pass_x86_64_fail_repro",
          pass_fn=passes.fuse_pass,
          arch=snapshot_pb2.Snapshot.X86_64,
          initial_bytes=b"\x90\x90\x90\xc3",
          trace_rounds=[
              [
                  "1 addr=0x1000 size=1 nop",
                  "2 addr=0x1001 size=1 nop",
                  "3 addr=0x1002 size=1 nop",
                  "4 addr=0x1003 size=1 ret",
              ],
          ],
          expected_bytes=b"\x90\x90\x90\xc3",
          expected_success=False,
          repro_results=itertools.repeat(False),
      ),
      dict(
          testcase_name="swap_pass_x86_64_success",
          pass_fn=passes.swap_pass,
          arch=snapshot_pb2.Snapshot.X86_64,
          initial_bytes=b"\xb8\x01\x00\x00\x00\x90\xc3",
          trace_rounds=[
              [
                  "1 addr=0x1000 size=5 mov eax, 1",
                  "2 addr=0x1005 size=1 nop",
                  "3 addr=0x1006 size=1 ret",
              ],
          ],
          expected_bytes=b"\x90\xb8\x01\x00\x00\x00\xc3",
          expected_success=True,
          repro_results=[True],
      ),
      dict(
          testcase_name="swap_pass_aarch64_success",
          pass_fn=passes.swap_pass,
          arch=snapshot_pb2.Snapshot.AARCH64,
          initial_bytes=b"\x20\x00\x80\xd2\x1f\x20\x03\xd5\xc0\x03\x5f\xd6",
          trace_rounds=[
              [
                  "1 addr=0x1000 mov x0, 1",
                  "2 addr=0x1004 nop",
                  "3 addr=0x1008 ret",
              ],
          ],
          expected_bytes=b"\x1f\x20\x03\xd5\x20\x00\x80\xd2\xc0\x03\x5f\xd6",
          expected_success=True,
          repro_results=[True],
      ),
      dict(
          testcase_name="swap_pass_x86_64_fail_repro",
          pass_fn=passes.swap_pass,
          arch=snapshot_pb2.Snapshot.X86_64,
          initial_bytes=b"\xb8\x01\x00\x00\x00\x90\xc3",
          trace_rounds=[
              [
                  "1 addr=0x1000 size=5 mov eax, 1",
                  "2 addr=0x1005 size=1 nop",
                  "3 addr=0x1006 size=1 ret",
              ],
          ],
          expected_bytes=b"\xb8\x01\x00\x00\x00\x90\xc3",
          expected_success=False,
          repro_results=[False],
      ),
      dict(
          testcase_name="swap_pass_x86_64_fail_no_nops",
          pass_fn=passes.swap_pass,
          arch=snapshot_pb2.Snapshot.X86_64,
          initial_bytes=b"\xb8\x01\x00\x00\x00\xc3",
          trace_rounds=[
              ["1 addr=0x1000 size=5 mov eax, 1", "2 addr=0x1005 size=1 ret"],
          ],
          expected_bytes=b"\xb8\x01\x00\x00\x00\xc3",
          expected_success=False,
          repro_results=[],
      ),
      dict(
          testcase_name="swap_pass_x86_64_fail_non_adjacent_nop",
          pass_fn=passes.swap_pass,
          arch=snapshot_pb2.Snapshot.X86_64,
          initial_bytes=b"\xe9\x01\x00\x00\x00\xcc\x90\xc3",
          trace_rounds=[
              [
                  "1 addr=0x1000 size=5 jmp 0x1006",
                  "2 addr=0x1006 size=1 nop",
                  "3 addr=0x1007 size=1 ret",
              ],
          ],
          expected_bytes=b"\xe9\x01\x00\x00\x00\xcc\x90\xc3",
          expected_success=False,
          repro_results=[],
      ),
      dict(
          testcase_name="swap_pass_x86_64_fail_leading_nops",
          pass_fn=passes.swap_pass,
          arch=snapshot_pb2.Snapshot.X86_64,
          initial_bytes=b"\x90\x90\x90\xb8\x01\x00\x00\x00\xc3",
          trace_rounds=[
              [
                  "1 addr=0x1000 size=1 nop",
                  "2 addr=0x1001 size=1 nop",
                  "3 addr=0x1002 size=1 nop",
                  "4 addr=0x1003 size=5 mov eax, 1",
                  "5 addr=0x1008 size=1 ret",
              ],
          ],
          expected_bytes=b"\x90\x90\x90\xb8\x01\x00\x00\x00\xc3",
          expected_success=False,
          repro_results=[],
      ),
      dict(
          testcase_name="elide_pass_x86_64_success",
          pass_fn=passes.elide_pass,
          arch=snapshot_pb2.Snapshot.X86_64,
          initial_bytes=b"\x90\x90\xb8\x01\x00\x00\x00\xc3",
          trace_rounds=[
              [
                  "1 addr=0x1000 size=1 nop",
                  "2 addr=0x1001 size=1 nop",
                  "3 addr=0x1002 size=5 mov eax, 1",
                  "4 addr=0x1007 size=1 ret",
              ],
          ],
          expected_bytes=b"\x90\x90\xb8\x01\x00\x00\x00\xc3",
          expected_success=True,
          repro_results=[True],
          expected_pc=0x1002,
      ),
      dict(
          testcase_name="elide_pass_x86_64_fail_no_nops",
          pass_fn=passes.elide_pass,
          arch=snapshot_pb2.Snapshot.X86_64,
          initial_bytes=b"\xb8\x01\x00\x00\x00\xc3",
          trace_rounds=[
              [
                  "1 addr=0x1000 size=5 mov eax, 1",
                  "2 addr=0x1005 size=1 ret",
              ],
          ],
          expected_bytes=b"\xb8\x01\x00\x00\x00\xc3",
          expected_success=False,
          repro_results=[False],
          expected_pc=None,
      ),
      dict(
          testcase_name="elide_pass_x86_64_fail_repro",
          pass_fn=passes.elide_pass,
          arch=snapshot_pb2.Snapshot.X86_64,
          initial_bytes=b"\x90\x90\x90\x90\xc3",
          trace_rounds=[
              [
                  "1 addr=0x1000 size=1 nop",
                  "2 addr=0x1001 size=1 nop",
                  "3 addr=0x1002 size=1 nop",
                  "4 addr=0x1003 size=1 ret",
              ],
          ],
          expected_bytes=b"\x90\x90\x90\x90\xc3",
          expected_success=False,
          repro_results=[False],
          expected_pc=None,
      ),
      dict(
          testcase_name="omit_pass_aarch64_success",
          pass_fn=passes.omit_pass,
          arch=snapshot_pb2.Snapshot.AARCH64,
          initial_bytes=b"\x1f\x20\x03\xd5\x20\x00\x80\xd2\xc0\x03\x5f\xd6",
          trace_rounds=[
              [
                  "1 addr=0x1000 nop",
                  "2 addr=0x1004 mov x0, 1",
                  "3 addr=0x1008 ret",
              ],
          ],
          expected_bytes=b"\x20\x00\x80\xd2\xc0\x03\x5f\xd6",
          expected_success=True,
          repro_results=[True],
      ),
      dict(
          testcase_name="omit_pass_aarch64_fail_no_nops",
          pass_fn=passes.omit_pass,
          arch=snapshot_pb2.Snapshot.AARCH64,
          initial_bytes=b"\x20\x00\x80\xd2\xc0\x03\x5f\xd6",
          trace_rounds=[
              [
                  "1 addr=0x1000 mov x0, 1",
                  "2 addr=0x1004 ret",
              ],
          ],
          expected_bytes=b"\x20\x00\x80\xd2\xc0\x03\x5f\xd6",
          expected_success=False,
          repro_results=[],
      ),
      dict(
          testcase_name="omit_pass_aarch64_fail_repro",
          pass_fn=passes.omit_pass,
          arch=snapshot_pb2.Snapshot.AARCH64,
          initial_bytes=b"\x1f\x20\x03\xd5\x20\x00\x80\xd2\xc0\x03\x5f\xd6",
          trace_rounds=[
              [
                  "1 addr=0x1000 nop",
                  "2 addr=0x1004 mov x0, 1",
                  "3 addr=0x1008 ret",
              ],
          ],
          expected_bytes=b"\x1f\x20\x03\xd5\x20\x00\x80\xd2\xc0\x03\x5f\xd6",
          expected_success=False,
          repro_results=[False],
      ),
  )
  def test_passes(
      self,
      pass_fn: passes.PassFunction,
      arch: snapshot_pb2.Snapshot.Architecture,
      initial_bytes: bytes,
      trace_rounds: list[list[str]],
      expected_bytes: bytes,
      expected_success: bool,
      expected_pc: int | None = None,
      repro_results: Iterable[bool] | None = None,
  ) -> None:
    self.mock_host.return_value = arch
    # Make random.shuffle a no-op to ensure a deterministic order of
    # instruction processing, preventing test brittleness due to RNG changes.
    mock_random_shuffle = self.enter_context(
        mock.patch.object(random.Random, "shuffle", autospec=True)
    )
    mock_random_shuffle.side_effect = lambda *_, **__: None
    snap = snapshot_pb2.Snapshot(
        id="test_snap",
        architecture=arch,
        memory_bytes=[
            snapshot_pb2.MemoryBytes(
                start_address=0x1000, byte_values=initial_bytes
            )
        ],
    )
    diff_engine = FakeDifferentialEngine(
        initial_snapshot=snap,
        trace_rounds=trace_rounds,
        repro_results=repro_results,
    )

    success = pass_fn(diff_engine, passes.default_pass_config())
    self.assertEqual(success, expected_success)
    snap = diff_engine.export_snapshot()
    with self.subTest(name="memory_bytes"):
      self.assertEqual(
          snap.memory_bytes[0].byte_values,
          expected_bytes,
      )
    with self.subTest(name="pc"):
      self.assertEqual(
          diff_engine.get_pc(snap),
          expected_pc,
      )

  @parameterized.named_parameters(
      dict(
          testcase_name="nop_pass",
          pass_fn=passes.nop_pass,
          expected_pass_name="nop_pass",
          expected_pass_default_order=schedule_pb2.PassConfig.RANDOM_ORDER,
          expected_invalidation=False,
      ),
      dict(
          testcase_name="fuse_pass",
          pass_fn=passes.fuse_pass,
          expected_pass_name="fuse_pass",
          expected_pass_default_order=schedule_pb2.PassConfig.RANDOM_ORDER,
          expected_invalidation=False,
      ),
      dict(
          testcase_name="swap_pass",
          pass_fn=passes.swap_pass,
          expected_pass_name="swap_pass",
          expected_pass_default_order=schedule_pb2.PassConfig.RANDOM_ORDER,
          expected_invalidation=False,
      ),
      dict(
          testcase_name="omit_pass",
          pass_fn=passes.omit_pass,
          expected_pass_name="omit_pass",
          expected_pass_default_order=schedule_pb2.PassConfig.FORWARD_ORDER,
          expected_invalidation=True,
      ),
  )
  def test_pass_wiring(
      self,
      pass_fn: passes.PassFunction,
      expected_pass_name: str,
      expected_pass_default_order: schedule_pb2.PassConfig.CandidateOrder,
      expected_invalidation: bool,
  ) -> None:
    self.mock_host.return_value = snapshot_pb2.Snapshot.X86_64
    snap = snapshot_pb2.Snapshot(
        id="test_snap", architecture=snapshot_pb2.Snapshot.X86_64
    )
    diff_engine = FakeDifferentialEngine(
        initial_snapshot=snap, trace_rounds=[["1 addr=0x1000 size=1 nop"]]
    )
    config = schedule_pb2.PassConfig(
        max_successes=1, max_consecutive_failures=5, max_iterations=10
    )

    with mock.patch.object(
        passes, "run_iterative_pass", autospec=True
    ) as mock_run:
      mock_run.return_value = True
      success = pass_fn(diff_engine, config)
      self.assertTrue(success)
      mock_run.assert_called_once_with(
          pass_name=expected_pass_name,
          diff_engine=diff_engine,
          config=config,
          find_candidates_fn=mock.ANY,
          mutate_candidate_fn=mock.ANY,
          pass_default_order=expected_pass_default_order,
          mutation_invalidates_candidates=expected_invalidation,
      )


class RunIterativePassTest(parameterized.TestCase):

  def setUp(self) -> None:
    super().setUp()
    self.mock_host = self.enter_context(
        mock.patch.object(engine, "host_platform", autospec=True)
    )
    self.mock_host.return_value = snapshot_pb2.Snapshot.X86_64
    self.snap = snapshot_pb2.Snapshot(
        id="test_snap", architecture=snapshot_pb2.Snapshot.X86_64
    )
    self.default_config = schedule_pb2.PassConfig(
        max_successes=10, max_consecutive_failures=5, max_iterations=10
    )

  @parameterized.named_parameters(
      dict(
          testcase_name="mutation_invalidates_candidates",
          num_rounds=2,
          config_overrides=dict(),
          find_side_effect=[[1, 2, 3], [1, 2, 3]],
          mutate_side_effect=[True, True],
          mutation_invalidates_candidates=True,
          expected_success=True,
          expected_mutate_args=[1, 1],
      ),
      dict(
          testcase_name="budget_cutoff_consecutive_failures",
          config_overrides=dict(max_consecutive_failures=3),
          find_side_effect=[[1, 2, 3, 4, 5, 6]],
          mutate_side_effect=[False, False, False, False, False, False],
          mutation_invalidates_candidates=False,
          expected_success=False,
          expected_mutate_args=[1, 2, 3],
      ),
      dict(
          testcase_name="budget_cutoff_max_successes",
          config_overrides=dict(max_successes=2),
          find_side_effect=[[1, 2, 3, 4, 5]],
          mutate_side_effect=[True, True, True, True, True],
          mutation_invalidates_candidates=False,
          expected_success=True,
          expected_mutate_args=[1, 2],
      ),
      dict(
          testcase_name="multi_iteration",
          num_rounds=3,
          config_overrides=dict(max_iterations=3),
          find_side_effect=[[1, 2], [3, 4], [5, 6]],
          mutate_side_effect=[False, True, False, True, False, True],
          mutation_invalidates_candidates=False,
          expected_success=True,
          expected_mutate_args=[1, 2, 3, 4, 5, 6],
      ),
  )
  def test_run_iterative_pass(
      self,
      config_overrides: dict[str, int],
      find_side_effect: list[list[int]],
      mutate_side_effect: list[bool],
      mutation_invalidates_candidates: bool,
      expected_success: bool,
      expected_mutate_args: list[int],
      *,
      num_rounds: int = 1,
  ) -> None:
    trace_rounds = [
        [
            f"1 addr={0x1000 + i:#x} size=1 nop",
            "2 addr=0x1003 size=1 ret",
        ]
        for i in range(num_rounds)
    ]
    expected_find_args = [
        [insn.Insn(addr=0x1000 + i, len=1, repr="nop")]
        for i in range(num_rounds)
    ]

    diff_engine = FakeDifferentialEngine(
        initial_snapshot=self.snap,
        trace_rounds=trace_rounds,
    )
    config = schedule_pb2.PassConfig()
    config.CopyFrom(self.default_config)
    override_config = schedule_pb2.PassConfig(**config_overrides)
    config.MergeFrom(override_config)

    mock_find = mock.Mock(side_effect=find_side_effect, spec_set=True)
    mock_mutate = mock.Mock(side_effect=mutate_side_effect, spec_set=True)

    success = passes.run_iterative_pass(
        pass_name="test_pass",
        diff_engine=diff_engine,
        config=config,
        find_candidates_fn=mock_find,
        mutate_candidate_fn=mock_mutate,
        pass_default_order=schedule_pb2.PassConfig.FORWARD_ORDER,
        mutation_invalidates_candidates=mutation_invalidates_candidates,
    )
    self.assertEqual(success, expected_success)
    self.assertEqual(
        mock_find.call_args_list,
        [mock.call(args) for args in expected_find_args],
    )
    self.assertEqual(
        mock_mutate.call_args_list,
        [mock.call(arg) for arg in expected_mutate_args],
    )

  @parameterized.named_parameters(
      dict(
          testcase_name="random_default_seed",
          config_overrides=dict(),
          pass_default_order=schedule_pb2.PassConfig.RANDOM_ORDER,
          expected_random_seed="test_snap",
          expected_mutate_args=[2, 3, 4, 5, 1],
      ),
      dict(
          testcase_name="random_explicit_seed",
          config_overrides=dict(
              candidate_order=schedule_pb2.PassConfig.RANDOM_ORDER, seed=123456
          ),
          pass_default_order=schedule_pb2.PassConfig.FORWARD_ORDER,
          expected_random_seed=123456,
          expected_mutate_args=[2, 3, 4, 5, 1],
      ),
      dict(
          testcase_name="reverse",
          config_overrides=dict(
              candidate_order=schedule_pb2.PassConfig.REVERSE_ORDER
          ),
          pass_default_order=schedule_pb2.PassConfig.FORWARD_ORDER,
          expected_random_seed=None,
          expected_mutate_args=[5, 4, 3, 2, 1],
      ),
      dict(
          testcase_name="forward",
          config_overrides=dict(
              candidate_order=schedule_pb2.PassConfig.FORWARD_ORDER
          ),
          pass_default_order=schedule_pb2.PassConfig.FORWARD_ORDER,
          expected_random_seed=None,
          expected_mutate_args=[1, 2, 3, 4, 5],
      ),
  )
  def test_candidate_order(
      self,
      config_overrides: Mapping[str, Any],
      pass_default_order: schedule_pb2.PassConfig.CandidateOrder,
      expected_random_seed: str | int | None,
      expected_mutate_args: Sequence[int],
  ) -> None:
    diff_engine = FakeDifferentialEngine(
        initial_snapshot=self.snap,
        trace_rounds=[["1 addr=0x1000 size=1 nop", "2 addr=0x1001 size=1 ret"]],
    )
    mock_find = mock.Mock(return_value=[1, 2, 3, 4, 5], spec_set=True)
    mock_mutate = mock.Mock(return_value=False, spec_set=True)

    config = schedule_pb2.PassConfig()
    config.CopyFrom(self.default_config)
    override_config = schedule_pb2.PassConfig(**config_overrides)
    config.MergeFrom(override_config)

    mock_random_cls = self.enter_context(
        mock.patch.object(random, "Random", autospec=True)
    )
    mock_rng = mock_random_cls.return_value
    # Simulate shuffling by rotating the list.
    mock_rng.shuffle.side_effect = lambda lst: lst.append(lst.pop(0))

    passes.run_iterative_pass(
        pass_name="test_pass",
        diff_engine=diff_engine,
        config=config,
        find_candidates_fn=mock_find,
        mutate_candidate_fn=mock_mutate,
        pass_default_order=pass_default_order,
        mutation_invalidates_candidates=False,
    )

    if expected_random_seed is not None:
      mock_random_cls.assert_called_once_with(expected_random_seed)
      mock_rng.shuffle.assert_called_once()
    else:
      mock_random_cls.assert_not_called()

    expected_insns = [insn.Insn(addr=0x1000, len=1, repr="nop")]
    self.assertEqual(mock_find.call_args_list, [mock.call(expected_insns)])
    self.assertEqual(
        mock_mutate.call_args_list,
        [mock.call(x) for x in expected_mutate_args],
    )

  def test_trace_runtime_error(self) -> None:
    diff_engine = FakeDifferentialEngine(
        initial_snapshot=self.snap,
        trace_rounds=[["1 addr=0x1000 size=1 nop"]],
    )
    with mock.patch.object(
        diff_engine, "trace_insns", autospec=True
    ) as mock_trace:
      mock_trace.side_effect = RuntimeError("snap_tool trace failed")
      success = passes.run_iterative_pass(
          pass_name="test_pass",
          diff_engine=diff_engine,
          config=self.default_config,
          find_candidates_fn=lambda _: [1],
          mutate_candidate_fn=lambda _: True,
          pass_default_order=schedule_pb2.PassConfig.FORWARD_ORDER,
          mutation_invalidates_candidates=False,
      )
      self.assertFalse(success)


if __name__ == "__main__":
  absltest.main()
