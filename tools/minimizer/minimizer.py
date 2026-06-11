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

"""SiliFuzz minimizer CLI driver.

This tool minimizes SiliFuzz snapshot reproducers by removing unneeded
instructions or mutating the snapshot while maintaining the original failure.
"""

from collections.abc import Mapping, Sequence

from absl import app
from absl import flags
from absl import logging

from proto import snapshot_pb2
from tools.minimizer import engine
from tools.minimizer import file_util
from tools.minimizer import passes
from tools.minimizer import schedule_pb2

_SNAPSHOT = flags.DEFINE_string(
    "snapshot", None, "Path to the input snapshot protobuf file.", required=True
)
_OUT = flags.DEFINE_string(
    "out",
    None,
    "Path to write the minimized snapshot protobuf file.",
    required=True,
)
_GOOD_CPU = flags.DEFINE_integer(
    "good_cpu",
    None,
    "Target good CPU core ID for differential execution.",
    lower_bound=0,
    required=True,
)
_BAD_CPU = flags.DEFINE_integer(
    "bad_cpu",
    None,
    "Target bad CPU core ID for differential execution.",
    lower_bound=0,
    required=True,
)
_MAX_GOOD_ITERATIONS = flags.DEFINE_integer(
    "max_good_iterations",
    engine.DEFAULT_MAX_GOOD_ITERATIONS,
    "Maximum number of iterations to run on the good CPU.",
    lower_bound=1,
)
_MAX_BAD_ITERATIONS = flags.DEFINE_integer(
    "max_bad_iterations",
    engine.DEFAULT_MAX_BAD_ITERATIONS,
    "Maximum number of iterations to run on the bad CPU.",
    lower_bound=1,
)
_PASSES = flags.DEFINE_multi_enum_class(
    "passes",
    None,
    passes.PassKind,
    "List of minimization passes to run. If unset, defaults to "
    "architecture-specific schedule.",
)
_RUNNER = flags.DEFINE_string(
    "runner",
    None,
    "Optional path to override the reading_runner binary. In normal usage, do "
    "NOT set this flag; the correct version-matched binary is auto-resolved.",
)
_SNAP_TOOL = flags.DEFINE_string(
    "snap_tool",
    None,
    "Optional path to override the snap_tool binary. In normal usage, do NOT "
    "set this flag; the correct version-matched binary is auto-resolved.",
)
_MAX_SUCCESSES = flags.DEFINE_integer(
    "max_successes",
    None,
    "Maximum number of successful operations per pass. If unset or negative, "
    "defaults to unconstrained.",
)
_MAX_CONSECUTIVE_FAILURES = flags.DEFINE_integer(
    "max_consecutive_failures",
    None,
    "Abort pass early after N consecutive try_modify failures. If unset, "
    "defaults to 10. Negative means unconstrained.",
)
_MAX_ITERATIONS = flags.DEFINE_integer(
    "max_iterations",
    None,
    "Maximum outer convergence rounds per pass. Negative or unset means "
    "unconstrained.",
)
_CANDIDATE_ORDER = flags.DEFINE_enum(
    "candidate_order",
    "DEFAULT_ORDER",
    schedule_pb2.PassConfig.CandidateOrder.keys(),
    "Explicit candidate execution ordering. If DEFAULT_ORDER, uses"
    " pass-specific defaults.",
)
_SEED = flags.DEFINE_integer(
    "seed",
    None,
    "Optional seed for RANDOM_ORDER candidate selection. If unset, defaults to"
    " snapshot ID hash.",
)


@flags.validator(_SNAPSHOT, "Snapshot path must be provided.")
def _validate_snapshot_path(path: str) -> bool:
  return bool(path)


@flags.validator(_OUT, "Output path must be provided.")
def _validate_output_path(path: str) -> bool:
  return bool(path)


@flags.multi_flags_validator(
    [_GOOD_CPU, _BAD_CPU],
    "good_cpu and bad_cpu must be distinct CPU core IDs.",
)
def _validate_cpu_flags(flags_dict: Mapping[str, int]) -> bool:
  return flags_dict[_GOOD_CPU.name] != flags_dict[_BAD_CPU.name]


def _resolve_flag_budget(val: int | None, default_val: int) -> int:
  """Resolves CLI budget flag values into definitive PassConfig integer fields.

  Args:
    val: The raw integer flag value (or None if unset).
    default_val: The baseline session default to apply if unset.

  Returns:
    The resolved budget integer.
  """
  if val is None:
    return default_val
  return passes.MAX_BUDGET if val < 0 else min(val, passes.MAX_BUDGET)


def main(argv: Sequence[str]) -> None:
  """Drives the SiliFuzz minimizer CLI.

  Args:
    argv: Command-line arguments.

  Raises:
    absl.app.UsageError: If invalid arguments are provided, or if the snapshot
      fails to load or save.
  """
  if len(argv) > 1:
    raise app.UsageError("Too many command-line arguments.")

  logging.info("Loading snapshot from %s", _SNAPSHOT.value)
  try:
    with file_util.open_file(_SNAPSHOT.value, "rb") as f:
      snapshot = snapshot_pb2.Snapshot.FromString(f.read())
  except Exception as e:
    raise app.UsageError(
        f"Failed to load snapshot from {_SNAPSHOT.value}"
    ) from e
  logging.info(
      "Successfully loaded snapshot %s (arch: %s)",
      snapshot.id,
      snapshot.architecture,
  )

  try:
    executor = engine.ToolExecutor(
        runner_path=_RUNNER.value,
        snap_tool_path=_SNAP_TOOL.value,
    )
    diff_engine = engine.DifferentialEngine(
        snapshot=snapshot,
        good_cpu=_GOOD_CPU.value,
        bad_cpu=_BAD_CPU.value,
        max_good_iterations=_MAX_GOOD_ITERATIONS.value,
        max_bad_iterations=_MAX_BAD_ITERATIONS.value,
        tool_executor=executor,
    )
  except ValueError as e:
    raise app.UsageError("Failed to initialize differential engine") from e

  if _PASSES.value is not None:
    schedule_passes = _PASSES.value
  elif snapshot.architecture not in passes.DEFAULT_PASSES_BY_ARCH:
    raise app.UsageError(
        "No default minimization schedule for architecture "
        f"{snapshot_pb2.Snapshot.Architecture.Name(snapshot.architecture)}"
    )
  else:
    schedule_passes = passes.DEFAULT_PASSES_BY_ARCH[snapshot.architecture]

  default_config = passes.default_pass_config()
  pass_config = schedule_pb2.PassConfig(
      max_successes=_resolve_flag_budget(
          _MAX_SUCCESSES.value, default_config.max_successes
      ),
      max_consecutive_failures=_resolve_flag_budget(
          _MAX_CONSECUTIVE_FAILURES.value,
          default_config.max_consecutive_failures,
      ),
      max_iterations=_resolve_flag_budget(
          _MAX_ITERATIONS.value, default_config.max_iterations
      ),
      candidate_order=schedule_pb2.PassConfig.CandidateOrder.Value(
          _CANDIDATE_ORDER.value
      ),
  )
  if _SEED.value is not None:
    pass_config.seed = _SEED.value

  logging.info(
      "Executing minimization schedule: %s (config: %s)",
      ", ".join(p.value for p in schedule_passes),
      pass_config,
  )
  for pass_kind in schedule_passes:
    if pass_kind not in passes.PASS_FN_BY_KIND:
      raise app.UsageError(f"Pass {pass_kind.value} is not implemented.")
    pass_fn = passes.PASS_FN_BY_KIND[pass_kind]
    pass_fn(diff_engine, pass_config)

  logging.info("Saving snapshot to %s", _OUT.value)
  try:
    with file_util.open_file(_OUT.value, "wb") as f:
      f.write(diff_engine.export_snapshot().SerializeToString())
  except Exception as e:
    raise app.UsageError(f"Failed to save snapshot to {_OUT.value}") from e


if __name__ == "__main__":
  app.run(main)
