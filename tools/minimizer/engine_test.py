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

import os
import platform
import subprocess
from unittest import mock

from absl.testing import absltest
from absl.testing import parameterized

from proto import player_result_pb2
from proto import snapshot_execution_result_pb2
from proto import snapshot_pb2
from tools.minimizer import engine
from tools.minimizer import file_util
from tools.minimizer import insn


class EngineTest(parameterized.TestCase):

  def setUp(self) -> None:
    super().setUp()
    engine.host_platform.cache_clear()
    self._temp_dir = self.create_tempdir()
    self._fake_tool = os.path.join(self._temp_dir, "fake_tool")
    with file_util.open_file(self._fake_tool, "w") as f:
      f.write("#!/bin/sh\necho 'fake'\n")
    os.chmod(self._fake_tool, 0o755)

  @parameterized.named_parameters(
      dict(
          testcase_name="x86_64",
          machine_name="x86_64",
          expected_arch=snapshot_pb2.Snapshot.X86_64,
      ),
      dict(
          testcase_name="aarch64",
          machine_name="aarch64",
          expected_arch=snapshot_pb2.Snapshot.AARCH64,
      ),
  )
  @mock.patch.object(platform, "machine", autospec=True)
  def test_host_platform(
      self,
      mock_machine: mock.MagicMock,
      machine_name: str,
      expected_arch: snapshot_pb2.Snapshot.Architecture,
  ) -> None:
    mock_machine.return_value = machine_name
    arch = engine.host_platform()
    self.assertEqual(arch, expected_arch)

  @mock.patch.object(platform, "machine", autospec=True)
  def test_host_platform_unknown(self, mock_machine: mock.MagicMock) -> None:
    mock_machine.return_value = "unknown_arch"
    with self.assertRaisesRegex(RuntimeError, "Unknown host architecture"):
      engine.host_platform()

  @mock.patch.object(engine, "host_platform", autospec=True)
  def test_init_compatible(self, mock_host: mock.MagicMock) -> None:
    mock_host.return_value = snapshot_pb2.Snapshot.X86_64
    snap = snapshot_pb2.Snapshot(
        id="test_snap", architecture=snapshot_pb2.Snapshot.X86_64
    )
    diff_engine = engine.DifferentialEngine(
        snapshot=snap, good_cpu=0, bad_cpu=1
    )
    self.assertEqual(diff_engine.snapshot_id, "test_snap")
    self.assertEqual(diff_engine.architecture, snapshot_pb2.Snapshot.X86_64)

  @mock.patch.object(engine, "host_platform", autospec=True)
  def test_init_incompatible(self, mock_host: mock.MagicMock) -> None:
    mock_host.return_value = snapshot_pb2.Snapshot.AARCH64
    snap = snapshot_pb2.Snapshot(
        id="test_snap", architecture=snapshot_pb2.Snapshot.X86_64
    )
    with self.assertRaisesRegex(ValueError, "does not match host platform"):
      engine.DifferentialEngine(snapshot=snap, good_cpu=0, bad_cpu=1)

  @parameterized.named_parameters(
      dict(
          testcase_name="identical_cpus",
          good_cpu=0,
          bad_cpu=0,
          expected_error="distinct CPU core IDs",
      ),
      dict(
          testcase_name="negative_good_cpu",
          good_cpu=-1,
          expected_error="non-negative integers",
      ),
      dict(
          testcase_name="negative_bad_cpu",
          bad_cpu=-1,
          expected_error="non-negative integers",
      ),
      dict(
          testcase_name="zero_good_iterations",
          max_good_iterations=0,
          expected_error="positive integers",
      ),
      dict(
          testcase_name="zero_bad_iterations",
          max_bad_iterations=0,
          expected_error="positive integers",
      ),
  )
  @mock.patch.object(engine, "host_platform", autospec=True)
  def test_init_invalid_params(
      self,
      mock_host: mock.MagicMock,
      good_cpu: int = 0,
      bad_cpu: int = 1,
      max_good_iterations: int = 1,
      max_bad_iterations: int = 1,
      expected_error: str = ".*",
  ) -> None:
    mock_host.return_value = snapshot_pb2.Snapshot.X86_64
    snap = snapshot_pb2.Snapshot(
        id="test_snap", architecture=snapshot_pb2.Snapshot.X86_64
    )
    with self.assertRaisesRegex(ValueError, expected_error):
      engine.DifferentialEngine(
          snapshot=snap,
          good_cpu=good_cpu,
          bad_cpu=bad_cpu,
          max_good_iterations=max_good_iterations,
          max_bad_iterations=max_bad_iterations,
      )

  def test_tool_executor_init_file_not_found(self) -> None:
    with self.assertRaisesRegex(ValueError, "Required tool binary"):
      engine.ToolExecutor(runner_path="/nonexistent/runner")

  @mock.patch.object(subprocess, "run", autospec=True)
  def test_tool_executor_platform_id_success(
      self, mock_run: mock.MagicMock
  ) -> None:
    mock_run.return_value = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="intel_skylake\n", stderr=""
    )
    executor = engine.ToolExecutor(platform_id_path=self._fake_tool)
    result = executor.run_platform_id_tool()
    self.assertEqual(result, "intel_skylake")
    mock_run.assert_called_once_with(
        [self._fake_tool, "--short"],
        capture_output=mock.ANY,
        text=mock.ANY,
        check=mock.ANY,
    )

  @mock.patch.object(subprocess, "run", autospec=True)
  def test_tool_executor_platform_id_failure(
      self, mock_run: mock.MagicMock
  ) -> None:
    mock_run.return_value = subprocess.CompletedProcess(
        args=[], returncode=1, stdout="", stderr="error"
    )
    executor = engine.ToolExecutor(
        platform_id_path=self._fake_tool,
    )
    with self.assertRaisesRegex(RuntimeError, "silifuzz_platform_id failed"):
      executor.run_platform_id_tool()

  @mock.patch.object(subprocess, "run", autospec=True)
  def test_tool_executor_run_snap_tool_success(
      self, mock_run: mock.MagicMock
  ) -> None:
    mock_run.return_value = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="success", stderr=""
    )
    executor = engine.ToolExecutor(snap_tool_path=self._fake_tool)
    proc_result = executor.run_snap_tool(
        0, ["make", "file.pb"], output="out.pb"
    )
    self.assertEqual(proc_result.returncode, 0)
    self.assertEqual(proc_result.stdout, "success")
    mock_run.assert_called_once_with(
        [
            "taskset",
            "-c",
            "0",
            self._fake_tool,
            "--out",
            "out.pb",
            "make",
            "file.pb",
        ],
        capture_output=mock.ANY,
        text=mock.ANY,
        check=mock.ANY,
    )

  @mock.patch.object(subprocess, "run", autospec=True)
  def test_tool_executor_run_snap_tool_failure(
      self, mock_run: mock.MagicMock
  ) -> None:
    mock_run.return_value = subprocess.CompletedProcess(
        args=[], returncode=1, stdout="", stderr="error"
    )
    executor = engine.ToolExecutor(
        snap_tool_path=self._fake_tool,
    )
    with self.assertRaisesRegex(RuntimeError, "snap_tool failed"):
      executor.run_snap_tool(0, ["make", "file.pb"])
    mock_run.assert_called_once_with(
        ["taskset", "-c", "0", self._fake_tool, "make", "file.pb"],
        capture_output=mock.ANY,
        text=mock.ANY,
        check=mock.ANY,
    )

  @mock.patch.object(subprocess, "run", autospec=True)
  def test_tool_executor_execute_runner_success(
      self, mock_run: mock.MagicMock
  ) -> None:
    mock_run.return_value = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="", stderr=""
    )
    executor = engine.ToolExecutor(
        runner_path=self._fake_tool,
    )
    run_result = executor.execute_runner(0, "corpus", 1000)
    self.assertTrue(run_result.as_expected)
    mock_run.assert_called_once_with(
        [self._fake_tool, "--cpu", "0", "--num_iterations", "1000", "corpus"],
        capture_output=mock.ANY,
        text=mock.ANY,
        check=mock.ANY,
    )

  @mock.patch.object(subprocess, "run", autospec=True)
  def test_tool_executor_execute_runner_failure(
      self, mock_run: mock.MagicMock
  ) -> None:
    runner_out = snapshot_execution_result_pb2.RunnerOutput(
        execution_result=snapshot_execution_result_pb2.RunnerOutput.ExecutionResult(
            code=snapshot_execution_result_pb2.RunnerOutput.ExecutionResult.StatusCode.SNAPSHOT_FAILED,
        ),
        failed_snapshot_execution=snapshot_execution_result_pb2.SnapshotExecutionResult(
            player_result=player_result_pb2.PlayerResult(
                cpu_id=1,
                outcome=player_result_pb2.PlayerResult.ENDPOINT_MISMATCH,
            )
        ),
    )

    mock_run.return_value = subprocess.CompletedProcess(
        args=[],
        returncode=1,
        stdout=str(runner_out),
        stderr="Seed = 1234 iteration #500\n",
    )

    executor = engine.ToolExecutor(runner_path=self._fake_tool)
    actual_run_result = executor.execute_runner(1, "corpus", 1000)

    expected_run_result = engine.RunResult(
        proto=player_result_pb2.PlayerResult(
            cpu_id=1,
            outcome=player_result_pb2.PlayerResult.ENDPOINT_MISMATCH,
        ),
        seed="1234",
        elapsed_iterations=500,
    )
    self.assertEqual(actual_run_result, expected_run_result)
    mock_run.assert_called_once_with(
        [self._fake_tool, "--cpu", "1", "--num_iterations", "1000", "corpus"],
        capture_output=mock.ANY,
        text=mock.ANY,
        check=mock.ANY,
    )

  @mock.patch.object(engine, "host_platform", autospec=True)
  def test_trace(self, mock_host: mock.MagicMock) -> None:
    mock_host.return_value = snapshot_pb2.Snapshot.X86_64
    snap = snapshot_pb2.Snapshot(
        id="test_snap", architecture=snapshot_pb2.Snapshot.X86_64
    )
    mock_executor = mock.create_autospec(engine.ToolExecutor, instance=True)
    mock_executor.run_snap_tool.return_value = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="", stderr="line1\nline2\n"
    )
    diff_engine = engine.DifferentialEngine(
        snapshot=snap, good_cpu=0, bad_cpu=1, tool_executor=mock_executor
    )

    lines = diff_engine.trace()
    self.assertEqual(lines, ["line1", "line2"])

  @mock.patch.object(engine, "host_platform", autospec=True)
  def test_try_modify_success(self, mock_host: mock.MagicMock) -> None:
    good_cpu = 0
    bad_cpu = 1
    remade_snap_id = "remade_snap"
    mock_host.return_value = snapshot_pb2.Snapshot.X86_64
    snap = snapshot_pb2.Snapshot(
        id="test_snap", architecture=snapshot_pb2.Snapshot.X86_64
    )
    mock_executor = mock.create_autospec(engine.ToolExecutor, instance=True)
    mock_executor.run_platform_id_tool.return_value = "intel_skylake"

    def _run_snap_side_effect(
        cpu_id: int, command: list[str], output: str | None = None
    ) -> subprocess.CompletedProcess[str]:
      del cpu_id, command
      if output:
        with file_util.open_file(output, "wb") as f:
          dummy_snap = snapshot_pb2.Snapshot(
              id=remade_snap_id, architecture=snapshot_pb2.Snapshot.X86_64
          )
          f.write(dummy_snap.SerializeToString())
      return subprocess.CompletedProcess(
          args=[], returncode=0, stdout="success", stderr=""
      )

    mock_executor.run_snap_tool.side_effect = _run_snap_side_effect

    mock_executor.execute_runner.side_effect = [
        engine.RunResult(
            proto=player_result_pb2.PlayerResult(
                outcome=player_result_pb2.PlayerResult.AS_EXPECTED
            ),
            seed=None,
            elapsed_iterations=None,
        ),
        engine.RunResult(
            proto=player_result_pb2.PlayerResult(
                outcome=player_result_pb2.PlayerResult.ENDPOINT_MISMATCH
            ),
            seed="1234",
            elapsed_iterations=500,
        ),
    ]

    diff_engine = engine.DifferentialEngine(
        snapshot=snap,
        good_cpu=good_cpu,
        bad_cpu=bad_cpu,
        tool_executor=mock_executor,
    )

    success = diff_engine.try_modify(lambda out: True)
    self.assertTrue(success)
    self.assertEqual(diff_engine.snapshot_id, remade_snap_id)

  @mock.patch.object(engine, "host_platform", autospec=True)
  def test_set_bytes_success(self, mock_host: mock.MagicMock) -> None:
    mock_host.return_value = snapshot_pb2.Snapshot.X86_64
    snap = snapshot_pb2.Snapshot(
        id="test_snap",
        architecture=snapshot_pb2.Snapshot.X86_64,
        memory_bytes=[
            snapshot_pb2.MemoryBytes(
                start_address=0x1000, byte_values=b"\x01\x02\x03\x04"
            )
        ],
    )
    diff_engine = engine.DifferentialEngine(
        snapshot=snap, good_cpu=0, bad_cpu=1
    )
    success = diff_engine.set_bytes(snap, 0x1001, b"\x90\x90")
    self.assertTrue(success)
    self.assertEqual(snap.memory_bytes[0].byte_values, b"\x01\x90\x90\x04")

  @mock.patch.object(engine, "host_platform", autospec=True)
  def test_set_bytes_failure(self, mock_host: mock.MagicMock) -> None:
    mock_host.return_value = snapshot_pb2.Snapshot.X86_64
    snap = snapshot_pb2.Snapshot(
        id="test_snap",
        architecture=snapshot_pb2.Snapshot.X86_64,
        memory_bytes=[
            snapshot_pb2.MemoryBytes(
                start_address=0x1000, byte_values=b"\x01\x02\x03\x04"
            ),
        ],
    )
    diff_engine = engine.DifferentialEngine(
        snapshot=snap, good_cpu=0, bad_cpu=1
    )
    with self.subTest("unmapped_address"):
      success = diff_engine.set_bytes(snap, 0x2000, b"\x90")
      self.assertFalse(success)
    with self.subTest("partially_mapped_address"):
      success = diff_engine.set_bytes(snap, 0x1002, b"\x90\x90\x90")
      self.assertFalse(success)

  @mock.patch.object(engine, "host_platform", autospec=True)
  def test_get_bytes(self, mock_host: mock.MagicMock) -> None:
    mock_host.return_value = snapshot_pb2.Snapshot.X86_64
    snap = snapshot_pb2.Snapshot(
        id="test_snap",
        architecture=snapshot_pb2.Snapshot.X86_64,
        memory_bytes=[
            snapshot_pb2.MemoryBytes(
                start_address=0x1000, byte_values=b"\x01\x02\x03\x04"
            )
        ],
    )
    diff_engine = engine.DifferentialEngine(
        snapshot=snap, good_cpu=0, bad_cpu=1
    )

    with self.subTest("valid_range"):
      self.assertEqual(diff_engine.get_bytes(0x1001, 2), b"\x02\x03")
    with self.subTest("invalid_range"):
      with self.assertRaisesRegex(ValueError, "Cannot find mapped bytes"):
        diff_engine.get_bytes(0x2000, 2)
    with self.subTest("invalid_size"):
      with self.assertRaisesRegex(ValueError, "Size must be positive"):
        diff_engine.get_bytes(0x1000, 0)

  @mock.patch.object(engine, "host_platform", autospec=True)
  def test_set_pc_success(self, mock_host: mock.MagicMock) -> None:
    mock_host.return_value = snapshot_pb2.Snapshot.X86_64
    snap = snapshot_pb2.Snapshot(
        id="test_snap", architecture=snapshot_pb2.Snapshot.X86_64
    )
    mock_executor = mock.create_autospec(
        engine.ToolExecutor, spec_set=True, instance=True
    )

    def _run_snap_side_effect(
        cpu_id: int, command: list[str], output: str | None = None
    ) -> subprocess.CompletedProcess[str]:
      del cpu_id, command
      if output:
        with file_util.open_file(output, "wb") as f:
          modified_snap = snapshot_pb2.Snapshot()
          modified_snap.CopyFrom(snap)
          modified_snap.id = "modified_snap"
          f.write(modified_snap.SerializeToString())
      return subprocess.CompletedProcess(
          args=[], returncode=0, stdout="success", stderr=""
      )

    mock_executor.run_snap_tool.side_effect = _run_snap_side_effect

    diff_engine = engine.DifferentialEngine(
        snapshot=snap, good_cpu=0, bad_cpu=1, tool_executor=mock_executor
    )
    success = diff_engine.set_pc(snap, 0x1234)
    self.assertTrue(success)
    mock_executor.run_snap_tool.assert_called_once_with(
        cpu_id=mock.ANY,
        command=["set_pc", mock.ANY, "0x1234"],
        output=mock.ANY,
    )
    self.assertEqual(snap.id, "modified_snap")

  @mock.patch.object(engine, "host_platform", autospec=True)
  def test_set_pc_failure(self, mock_host: mock.MagicMock) -> None:
    mock_host.return_value = snapshot_pb2.Snapshot.X86_64
    snap = snapshot_pb2.Snapshot(
        id="test_snap", architecture=snapshot_pb2.Snapshot.X86_64
    )
    mock_executor = mock.create_autospec(engine.ToolExecutor, instance=True)
    mock_executor.run_snap_tool.side_effect = RuntimeError(
        "snap_tool set_pc failed"
    )

    diff_engine = engine.DifferentialEngine(
        snapshot=snap, good_cpu=0, bad_cpu=1, tool_executor=mock_executor
    )
    success = diff_engine.set_pc(snap, 0x1234)
    self.assertFalse(success)

  @mock.patch.object(engine, "host_platform", autospec=True)
  def test_trace_insns(self, mock_host: mock.MagicMock) -> None:
    mock_host.return_value = snapshot_pb2.Snapshot.X86_64
    snap = snapshot_pb2.Snapshot(
        id="test_snap", architecture=snapshot_pb2.Snapshot.X86_64
    )
    mock_executor = mock.create_autospec(engine.ToolExecutor, instance=True)
    mock_executor.run_snap_tool.return_value = subprocess.CompletedProcess(
        args=[],
        returncode=0,
        stdout="",
        stderr="1 addr=0x1000 size=5 mov eax, 1\n2 addr=0x1005 size=1 ret\n",
    )
    diff_engine = engine.DifferentialEngine(
        snapshot=snap, good_cpu=0, bad_cpu=1, tool_executor=mock_executor
    )

    insns = diff_engine.trace_insns()
    self.assertSequenceEqual(
        insns,
        [
            insn.Insn(
                addr=0x1000,
                len=5,
                repr="mov eax, 1",
            )
        ],
    )

  @parameterized.named_parameters(
      dict(
          testcase_name="valid_range",
          initial_bytes=b"\x01\x02\x03\x04",
          addr=0x1001,
          size=2,
          expected_success=True,
          expected_bytes=b"\x01\x04",
      ),
      dict(
          testcase_name="unmapped_address",
          initial_bytes=b"\x01\x02\x03\x04",
          addr=0x2000,
          size=2,
          expected_success=False,
          expected_bytes=b"\x01\x02\x03\x04",
      ),
      dict(
          testcase_name="partially_mapped_address",
          initial_bytes=b"\x01\x02\x03\x04",
          addr=0x1001,
          size=5,
          expected_success=False,
          expected_bytes=b"\x01\x02\x03\x04",
      ),
  )
  @mock.patch.object(engine, "host_platform", autospec=True)
  def test_delete_bytes(
      self,
      mock_host: mock.MagicMock,
      initial_bytes: bytes,
      addr: int,
      size: int,
      expected_success: bool,
      expected_bytes: bytes,
  ) -> None:
    mock_host.return_value = snapshot_pb2.Snapshot.X86_64
    snap = snapshot_pb2.Snapshot(
        id="test_snap",
        architecture=snapshot_pb2.Snapshot.X86_64,
        memory_bytes=[
            snapshot_pb2.MemoryBytes(
                start_address=0x1000, byte_values=initial_bytes
            )
        ],
    )
    diff_engine = engine.DifferentialEngine(
        snapshot=snap, good_cpu=0, bad_cpu=1
    )
    success = diff_engine.delete_bytes(snap, addr, size)
    self.assertEqual(success, expected_success)
    self.assertEqual(snap.memory_bytes[0].byte_values, expected_bytes)


if __name__ == "__main__":
  absltest.main()
