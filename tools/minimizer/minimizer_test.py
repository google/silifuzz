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

from collections.abc import Mapping
import os
import types
from typing import Any, override
from unittest import mock

from absl import app
from absl import flags
from absl.testing import absltest
from absl.testing import flagsaver
from absl.testing import parameterized

from proto import snapshot_pb2
from tools.minimizer import engine
from tools.minimizer import file_util
from tools.minimizer import minimizer
from tools.minimizer import passes


class MinimizerTest(parameterized.TestCase):

  @override
  def setUp(self) -> None:
    super().setUp()
    self.temp_dir = self.create_tempdir()
    self.snapshot_path = os.path.join(self.temp_dir, "input.pb")
    self.out_path = os.path.join(self.temp_dir, "output.pb")
    self.common_flags = dict(
        snapshot=self.snapshot_path,
        out=self.out_path,
        good_cpu=0,
        bad_cpu=1,
    )

    self.mock_host = mock.create_autospec(
        engine.host_platform, return_value=snapshot_pb2.Snapshot.X86_64
    )
    self.enter_context(
        mock.patch.object(engine, "host_platform", self.mock_host)
    )

    self.dummy_snapshot = snapshot_pb2.Snapshot(
        id="dummy_id", architecture=snapshot_pb2.Snapshot.X86_64
    )
    with file_util.open_file(self.snapshot_path, "wb") as f:
      f.write(self.dummy_snapshot.SerializeToString())

    self.mock_nop = mock.create_autospec(passes.PassFunction, return_value=True)
    self.mock_fuse = mock.create_autospec(
        passes.PassFunction, return_value=True
    )
    self.mock_swap = mock.create_autospec(
        passes.PassFunction, return_value=True
    )
    self.mock_elide = mock.create_autospec(
        passes.PassFunction, return_value=True
    )
    self.mock_registry = {
        passes.PassKind.NOP: self.mock_nop,
        passes.PassKind.FUSE: self.mock_fuse,
        passes.PassKind.SWAP: self.mock_swap,
        passes.PassKind.ELIDE: self.mock_elide,
    }
    self.enter_context(
        mock.patch.object(passes, "PASS_FN_BY_KIND", self.mock_registry)
    )

  def test_flags_valid(self) -> None:
    with flagsaver.flagsaver(**self.common_flags):
      flags.FLAGS.validate_all_flags()

  @parameterized.named_parameters(
      dict(
          testcase_name="missing_snapshot",
          flag_overrides=dict(snapshot=None),
          expected_error="--snapshot must have a value",
      ),
      dict(
          testcase_name="empty_snapshot",
          flag_overrides=dict(snapshot=""),
          expected_error="Snapshot path must be provided",
      ),
      dict(
          testcase_name="missing_out",
          flag_overrides=dict(out=None),
          expected_error="--out must have a value",
      ),
      dict(
          testcase_name="empty_out",
          flag_overrides=dict(out=""),
          expected_error="Output path must be provided",
      ),
      dict(
          testcase_name="identical_cpus",
          flag_overrides=dict(good_cpu=2, bad_cpu=2),
          expected_error="must be distinct",
      ),
      dict(
          testcase_name="negative_good_cpu",
          flag_overrides=dict(good_cpu=-1),
          expected_error="non-negative integer",
      ),
      dict(
          testcase_name="negative_bad_cpu",
          flag_overrides=dict(bad_cpu=-1),
          expected_error="non-negative integer",
      ),
      dict(
          testcase_name="negative_max_good_iterations",
          flag_overrides=dict(max_good_iterations=0),
          expected_error="positive integer",
      ),
      dict(
          testcase_name="negative_max_bad_iterations",
          flag_overrides=dict(max_bad_iterations=0),
          expected_error="positive integer",
      ),
      dict(
          testcase_name="unknown_pass",
          flag_as_parsed_overrides=dict(passes=["INVALID"]),
          expected_error="value should be one of",
      ),
  )
  def test_flags_invalid(
      self,
      expected_error: str,
      flag_overrides: Mapping[str, Any] = types.MappingProxyType({}),
      flag_as_parsed_overrides: Mapping[
          str, str
      ] = types.MappingProxyType({}),
  ) -> None:
    actual_flags = self.common_flags | flag_overrides
    with self.assertRaisesRegex(flags.IllegalFlagValueError, expected_error):
      # Only flagsaver can trigger required flag validators.
      with flagsaver.flagsaver(**actual_flags):
        flags.FLAGS.validate_all_flags()
      # Only as_parsed can trigger enum class flag validators.
      with flagsaver.as_parsed(**flag_as_parsed_overrides):
        pass

  def test_main_nonexist_snapshot(self) -> None:
    actual_flags = self.common_flags | dict(snapshot="nonexistent_path")
    with flagsaver.flagsaver(**actual_flags):
      with self.assertRaisesRegex(app.UsageError, "Failed to load snapshot"):
        minimizer.main(["minimizer.py"])

  def test_main_success_default_passes(self) -> None:
    mock_schedules = {
        snapshot_pb2.Snapshot.X86_64: (
            passes.PassKind.NOP,
            passes.PassKind.FUSE,
            passes.PassKind.SWAP,
            passes.PassKind.ELIDE,
        ),
    }

    with mock.patch.object(passes, "DEFAULT_PASSES_BY_ARCH", mock_schedules):
      with flagsaver.flagsaver(**self.common_flags):
        minimizer.main(["minimizer.py"])
        with self.subTest(name="Output file exists"):
          self.assertTrue(file_util.file_exists(self.out_path))
        with self.subTest(name="All passes called"):
          self.mock_nop.assert_called_once()
          self.mock_fuse.assert_called_once()
          self.mock_swap.assert_called_once()
          self.mock_elide.assert_called_once()

  def test_main_custom_passes_success(self) -> None:
    with flagsaver.flagsaver(
        **self.common_flags,
        passes=[passes.PassKind.NOP, passes.PassKind.SWAP],
    ):
      minimizer.main(["minimizer.py"])
      with self.subTest(name="Output file exists"):
        self.assertTrue(file_util.file_exists(self.out_path))
      with self.subTest(name="Only specified passes called"):
        self.mock_nop.assert_called_once()
        self.mock_swap.assert_called_once()
        self.mock_fuse.assert_not_called()
        self.mock_elide.assert_not_called()

  def test_main_candidate_order_seed_success(self) -> None:
    with flagsaver.flagsaver(
        **self.common_flags,
        passes=[passes.PassKind.NOP],
        candidate_order="RANDOM_ORDER",
        seed=12345,
    ):
      minimizer.main(["minimizer.py"])
      self.mock_nop.assert_called_once()
      pass_config = self.mock_nop.call_args[0][1]
      self.assertEqual(
          pass_config.candidate_order,
          minimizer.schedule_pb2.PassConfig.RANDOM_ORDER,
      )
      self.assertEqual(pass_config.seed, 12345)

  def test_main_incompatible_host(self) -> None:
    self.mock_host.return_value = snapshot_pb2.Snapshot.AARCH64
    with self.assertRaisesRegex(app.UsageError, "Failed to initialize"):
      with flagsaver.flagsaver(**self.common_flags):
        minimizer.main(["minimizer.py"])

  def test_main_too_many_args(self) -> None:
    with self.assertRaisesRegex(
        app.UsageError, "Too many command-line arguments"
    ):
      minimizer.main(["minimizer.py", "extra_arg"])


if __name__ == "__main__":
  flags.set_default(minimizer._SNAPSHOT, "path")
  flags.set_default(minimizer._OUT, "path")
  flags.set_default(minimizer._GOOD_CPU, 0)
  flags.set_default(minimizer._BAD_CPU, 1)
  absltest.main()
