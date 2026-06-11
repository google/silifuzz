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

"""Core execution engine for SiliFuzz differential minimization.

Encapsulates physical machine state, active snapshot state, and subprocess
orchestration.
"""

from collections.abc import Callable, Sequence
import dataclasses
import functools
import os
import platform
import re
import subprocess
import tempfile

from absl import logging
from google.protobuf import text_format

from proto import player_result_pb2
from proto import snapshot_execution_result_pb2
from proto import snapshot_pb2
from tools.minimizer import file_util
from tools.minimizer import insn

DEFAULT_MAX_GOOD_ITERATIONS = 1_000
DEFAULT_MAX_BAD_ITERATIONS = 1_000_000

_DEFAULT_RUNNER_RESOURCE: str = "runner/reading_runner_main_nolibc"
_DEFAULT_SNAP_TOOL_RESOURCE: str = "tools/snap_tool"
_DEFAULT_PLATFORM_ID_RESOURCE: str = "tools/silifuzz_platform_id"
_RUNNER_SEED_ITER_RE: re.Pattern[str] = re.compile(
    r"Seed = (?P<seed>\d+) iteration #(?P<iteration>\d+)"
)


@dataclasses.dataclass(frozen=True)
class RunResult:
  """Result of a differential runner execution.

  Attributes:
    proto: The PlayerResult proto from the runner output.
    seed: The seed used by the runner, if a failure occurred.
    elapsed_iterations: The number of iterations executed before termination, if
      a failure occurred.
  """

  proto: player_result_pb2.PlayerResult
  seed: str | None
  elapsed_iterations: int | None

  @property
  def as_expected(self) -> bool:
    """Whether the result matches the expected outcome."""
    return self.proto.outcome == player_result_pb2.PlayerResult.AS_EXPECTED


@functools.cache
def host_platform() -> snapshot_pb2.Snapshot.Architecture:
  """Queries physical host instruction set architecture (ISA).

  Returns:
    The SiliFuzz Snapshot Architecture enum corresponding to the host machine.

  Raises:
    RuntimeError: If the host architecture is unknown.
  """
  arch_str = platform.machine().lower()
  if arch_str in ("x86_64", "amd64"):
    return snapshot_pb2.Snapshot.X86_64
  if arch_str in ("aarch64", "arm64"):
    return snapshot_pb2.Snapshot.AARCH64
  raise RuntimeError(f"Unknown host architecture: {arch_str!r}")


class ToolExecutor:
  """SiliFuzz tool binary execution wrapper."""

  def __init__(
      self,
      *,
      runner_path: str | None = None,
      snap_tool_path: str | None = None,
      platform_id_path: str | None = None,
  ) -> None:
    """Initializes the ToolExecutor.

    Args:
      runner_path: Optional path to override the reading_runner binary. If not
        provided, the default path is used.
      snap_tool_path: Optional path to override the snap_tool binary. If not
        provided, the default path is used.
      platform_id_path: Optional path to override the silifuzz_platform_id
        binary. If not provided, the default path is used.

    Raises:
      ValueError: If a required tool binary is not an executable file.
    """

    self._runner_path = runner_path or file_util.get_resource_filename(
        _DEFAULT_RUNNER_RESOURCE
    )
    self._snap_tool_path = snap_tool_path or file_util.get_resource_filename(
        _DEFAULT_SNAP_TOOL_RESOURCE
    )
    self._platform_id_path = (
        platform_id_path
        or file_util.get_resource_filename(_DEFAULT_PLATFORM_ID_RESOURCE)
    )
    for path_name, path in [
        ("runner", self._runner_path),
        ("snap_tool", self._snap_tool_path),
        ("silifuzz_platform_id", self._platform_id_path),
    ]:
      if not os.access(path, os.X_OK):
        raise ValueError(
            f"Required tool binary {path_name!r} is not an executable file:"
            f" {path!r}"
        )

  def run_platform_id_tool(self) -> str:
    """Executes the silifuzz_platform_id tool.

    Returns:
      The platform ID string.

    Raises:
      RuntimeError: If silifuzz_platform_id fails (exit code != 0).
    """
    result = subprocess.run(
        [self._platform_id_path, "--short"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
      raise RuntimeError(
          f"silifuzz_platform_id failed with exit code {result.returncode}:\n"
          f"STDERR:\n{result.stderr}\nSTDOUT:\n{result.stdout}"
      )
    return result.stdout.strip()

  def run_snap_tool(
      self,
      cpu_id: int,
      command: Sequence[str],
      output: str | None = None,
  ) -> subprocess.CompletedProcess[str]:
    """Executes snap_tool bound to a specific CPU core via taskset.

    Args:
      cpu_id: The CPU core ID to bind execution to.
      command: List of arguments/subcommands for snap_tool.
      output: Optional path to write the output snapshot/corpus.

    Returns:
      A `subprocess.CompletedProcess` object containing the result of the
      command execution, including stdout and stderr.

    Raises:
      RuntimeError: If snap_tool fails (exit code != 0).
    """
    args = ["taskset", "-c", str(cpu_id), self._snap_tool_path]
    if output:
      args += ["--out", output]
    args += command
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if result.returncode != 0:
      raise RuntimeError(
          f"snap_tool failed running {args!r} on cpu {cpu_id} with exit code"
          f" {result.returncode}:\nSTDOUT:\n{result.stdout}\nSTDERR:"
          f"\n{result.stderr}"
      )
    return result

  def execute_runner(
      self, cpu_id: int, corpus_path: str, max_iterations: int
  ) -> RunResult:
    """Executes reading_runner bound to a specific CPU core via --cpu flag.

    Args:
      cpu_id: The CPU core ID to bind execution to.
      corpus_path: Path to the playable snapshot corpus file.
      max_iterations: Maximum iterations to execute.

    Returns:
      The RunResult instance encapsulating the outcome.

    Raises:
      RuntimeError: If the runner crashes unexpectedly or produces invalid
        output.
    """
    args = [
        self._runner_path,
        "--cpu",
        str(cpu_id),
        "--num_iterations",
        str(max_iterations),
        corpus_path,
    ]
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if result.returncode == 0:
      return RunResult(
          proto=player_result_pb2.PlayerResult(
              outcome=player_result_pb2.PlayerResult.AS_EXPECTED
          ),
          seed=None,
          elapsed_iterations=None,
      )

    try:
      runner_output = text_format.Parse(
          result.stdout, snapshot_execution_result_pb2.RunnerOutput()
      )
    except text_format.ParseError as e:
      raise RuntimeError(
          f"Failed to parse runner output proto:\ncode: {result.returncode}\n"
          f"STDERR:\n{result.stderr}\nSTDOUT:\n{result.stdout}"
      ) from e

    if (
        runner_output.execution_result.code
        != snapshot_execution_result_pb2.RunnerOutput.ExecutionResult.StatusCode.SNAPSHOT_FAILED
        or not runner_output.HasField("failed_snapshot_execution")
    ):
      raise RuntimeError(
          f"Runner failed with unexpected status (code {result.returncode}):\n"
          f"STDERR:\n{result.stderr}\nSTDOUT:\n{result.stdout}"
      )

    snapshot_failure = runner_output.failed_snapshot_execution
    if snapshot_failure.player_result.cpu_id != cpu_id:
      raise RuntimeError(
          "Runner executed on wrong CPU: got "
          f"{snapshot_failure.player_result.cpu_id}, "
          f"expected {cpu_id}"
      )

    match = _RUNNER_SEED_ITER_RE.search(result.stderr)
    seed = match.group("seed") if match else None
    elapsed_iterations = int(match.group("iteration")) if match else None

    return RunResult(
        proto=runner_output.failed_snapshot_execution.player_result,
        seed=seed,
        elapsed_iterations=elapsed_iterations,
    )


class DifferentialEngine:
  """Core execution engine for differential minimization.

  Encapsulates physical machine state, active snapshot state, and subprocess
  orchestration.
  """

  def __init__(
      self,
      snapshot: snapshot_pb2.Snapshot,
      *,
      good_cpu: int,
      bad_cpu: int,
      max_good_iterations: int = DEFAULT_MAX_GOOD_ITERATIONS,
      max_bad_iterations: int = DEFAULT_MAX_BAD_ITERATIONS,
      tool_executor: ToolExecutor | None = None,
  ) -> None:
    """Initializes the differential engine.

    Args:
      snapshot: The SiliFuzz Snapshot protobuf message to minimize.
      good_cpu: The target good CPU core ID for differential execution.
      bad_cpu: The target bad CPU core ID for differential execution.
      max_good_iterations: The maximum number of iterations to run on the good
        CPU.
      max_bad_iterations: The maximum number of iterations to run on the bad
        CPU.
      tool_executor: Optional ToolExecutor instance to use for subprocess
        execution. If not provided, a default instance is created.
    """
    self._active_snapshot = snapshot
    self._good_cpu = good_cpu
    self._bad_cpu = bad_cpu
    self._max_good_iterations = max_good_iterations
    self._max_bad_iterations = max_bad_iterations
    self._tool_executor = tool_executor or ToolExecutor()
    self._platform_id: str | None = None

    if good_cpu == bad_cpu:
      raise ValueError("good_cpu and bad_cpu must be distinct CPU core IDs.")
    if good_cpu < 0 or bad_cpu < 0:
      raise ValueError("CPU core IDs must be non-negative integers.")
    if max_good_iterations <= 0 or max_bad_iterations <= 0:
      raise ValueError("Iteration limits must be positive integers.")
    self.check_compatibility()

  @property
  def snapshot_id(self) -> str:
    """The active snapshot ID."""
    return self._active_snapshot.id

  @property
  def architecture(self) -> snapshot_pb2.Snapshot.Architecture:
    """The active snapshot architecture enum."""
    return self._active_snapshot.architecture

  def get_platform_id(self) -> str:
    """Queries and caches the physical host platform ID string."""
    if self._platform_id is None:
      self._platform_id = self._tool_executor.run_platform_id_tool()
    return self._platform_id

  def export_snapshot(self) -> snapshot_pb2.Snapshot:
    """Returns a deep copy of the active snapshot protobuf message."""
    candidate = snapshot_pb2.Snapshot()
    candidate.CopyFrom(self._active_snapshot)
    return candidate

  def check_compatibility(self) -> None:
    """Validates architectural compatibility against the physical host platform.

    Raises:
      ValueError: If snapshot architecture does not match host platform.
    """
    host_arch = host_platform()
    if self._active_snapshot.architecture != host_arch:
      raise ValueError(
          "Snapshot architecture"
          f" {snapshot_pb2.Snapshot.Architecture.Name(self._active_snapshot.architecture)}"
          " does not match host platform"
          f" {snapshot_pb2.Snapshot.Architecture.Name(host_arch)}."
      )

  def try_modify(
      self,
      mutation_fn: Callable[[snapshot_pb2.Snapshot], bool],
  ) -> bool:
    """Attempts a candidate mutation callback against the active snapshot.

    Args:
      mutation_fn: A callable accepting candidate_snapshot.

    Returns:
      True if minimization succeeded (active_snapshot updated), False otherwise.
    """
    candidate = snapshot_pb2.Snapshot()
    candidate.CopyFrom(self._active_snapshot)

    if not mutation_fn(candidate):
      return False

    with tempfile.TemporaryDirectory() as tmpdir:
      modified_pb = os.path.join(tmpdir, "modified.pb")
      remade_pb = os.path.join(tmpdir, "remade.pb")
      corpus = os.path.join(tmpdir, "corpus")

      with file_util.open_file(modified_pb, "wb") as f:
        f.write(candidate.SerializeToString())

      try:
        self._tool_executor.run_snap_tool(
            self._good_cpu, ["make", modified_pb], output=remade_pb
        )
        self._tool_executor.run_snap_tool(
            self._good_cpu,
            [
                "--target_platform",
                self.get_platform_id(),
                "generate_corpus",
                remade_pb,
            ],
            output=corpus,
        )
      except RuntimeError:
        logging.exception(
            "Corpus generation failed during try_modify", exc_info=True
        )
        return False

      try:
        good_result = self._tool_executor.execute_runner(
            self._good_cpu, corpus, self._max_good_iterations
        )
        bad_result = self._tool_executor.execute_runner(
            self._bad_cpu, corpus, self._max_bad_iterations
        )
      except RuntimeError:
        logging.exception(
            "Runner execution failed during try_modify", exc_info=True
        )
        return False

      if not good_result.as_expected:
        logging.debug("Modified snapshot failed on good CPU.")
        return False

      if bad_result.as_expected:
        logging.debug(
            "Modified snapshot failed to reproduce the failure on bad CPU."
        )
        return False

      logging.info(
          "Minimization succeeded. Num iterations to repro: %s",
          bad_result.elapsed_iterations,
      )
      with file_util.open_file(remade_pb, "rb") as f:
        self._active_snapshot = snapshot_pb2.Snapshot.FromString(f.read())
      return True

  def trace(self) -> list[str]:
    """Obtains execution trace of the active snapshot using snap_tool trace.

    Returns:
      List of raw trace output lines.

    Raises:
      RuntimeError: If snap_tool trace fails.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
      snap_pb = os.path.join(tmpdir, "active.pb")
      with file_util.open_file(snap_pb, "wb") as f:
        f.write(self._active_snapshot.SerializeToString())

      try:
        result = self._tool_executor.run_snap_tool(
            self._good_cpu, ["trace", snap_pb]
        )
        # snap_tool outputs trace to stderr instead of stdout.
        return result.stderr.splitlines()
      except RuntimeError as e:
        raise RuntimeError("snap_tool trace failed") from e

  def trace_insns(self) -> list[insn.Insn]:
    """Traces and parses instructions from the active snapshot.

    Returns:
      A list of parsed instructions (with the final exit/call instruction
      popped).

    Raises:
      RuntimeError: If tracing or parsing fails, or if no instructions are
        parsed.
    """
    lines = self.trace()

    try:
      insns = insn.parse_trace(lines, self.architecture)
    except ValueError as e:
      raise RuntimeError("Failed to parse trace") from e

    if not insns:
      raise RuntimeError("No instructions parsed from trace")

    # Pop the final exit/call instruction. This is always needed for the
    # snapshot to reach the endpoint.
    insns.pop()
    return insns

  @classmethod
  def set_bytes(
      cls, snapshot: snapshot_pb2.Snapshot, addr: int, data: bytes
  ) -> bool:
    """Modifies snapshot memory bytes in place at the specified address.

    Args:
      snapshot: The candidate Snapshot protobuf message to modify.
      addr: Target memory address.
      data: The new raw byte values to overwrite.

    Returns:
      True if bytes were successfully set, False if address range was unmapped.
    """
    data_size = len(data)
    for memory_block in snapshot.memory_bytes:
      if (
          memory_block.start_address <= addr
          and memory_block.start_address + len(memory_block.byte_values)
          >= addr + data_size
      ):
        offset = addr - memory_block.start_address
        buffer_view = memoryview(memory_block.byte_values)
        memory_block.byte_values = b"".join(
            (buffer_view[:offset], data, buffer_view[offset + data_size :])
        )
        return True
    return False

  @classmethod
  def delete_bytes(
      cls, snapshot: snapshot_pb2.Snapshot, addr: int, data_size: int
  ) -> bool:
    """Deletes snapshot memory bytes in place at the specified address.

    Args:
      snapshot: The candidate Snapshot protobuf message to modify.
      addr: Target memory address.
      data_size: Number of bytes to delete.

    Returns:
      True if bytes were successfully deleted, False if address range was
      unmapped.
    """
    for memory_block in snapshot.memory_bytes:
      if (
          memory_block.start_address <= addr
          and memory_block.start_address + len(memory_block.byte_values)
          >= addr + data_size
      ):
        offset = addr - memory_block.start_address
        buffer_view = memoryview(memory_block.byte_values)
        memory_block.byte_values = b"".join(
            (buffer_view[:offset], buffer_view[offset + data_size :])
        )
        return True
    return False

  def get_bytes(self, addr: int, data_size: int) -> bytes:
    """Retrieves raw memory bytes from the active snapshot at the specified address.

    Args:
      addr: Target memory address.
      data_size: Number of bytes to retrieve.

    Returns:
      The raw byte values.

    Raises:
      ValueError: If data_size is non-positive or address range is unmapped.
    """
    if data_size <= 0:
      raise ValueError(f"Size must be positive, got {data_size}.")
    for memory_block in self._active_snapshot.memory_bytes:
      if (
          memory_block.start_address <= addr
          and memory_block.start_address + len(memory_block.byte_values)
          >= addr + data_size
      ):
        offset = addr - memory_block.start_address
        return memory_block.byte_values[offset : offset + data_size]
    raise ValueError(
        f"Cannot find mapped bytes at 0x{addr:x} of size {data_size}"
    )

  def set_pc(self, snapshot: snapshot_pb2.Snapshot, pc: int) -> bool:
    """Modifies snapshot initial instruction pointer (PC/RIP) using snap_tool set_pc.

    Args:
      snapshot: The candidate Snapshot protobuf message to modify.
      pc: The new instruction pointer address.

    Returns:
      True if PC was successfully set, False otherwise.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
      tmp_in = os.path.join(tmpdir, "in.pb")
      tmp_out = os.path.join(tmpdir, "out.pb")
      with file_util.open_file(tmp_in, "wb") as f:
        f.write(snapshot.SerializeToString())

      try:
        self._tool_executor.run_snap_tool(
            self._good_cpu, ["set_pc", tmp_in, f"{pc:#x}"], output=tmp_out
        )
      except RuntimeError:
        logging.warning(
            "snap_tool set_pc failed setting PC to %#x",
            pc,
            exc_info=True,
        )
        return False

      with file_util.open_file(tmp_out, "rb") as f:
        snapshot.Clear()
        snapshot.ParseFromString(f.read())
      return True
