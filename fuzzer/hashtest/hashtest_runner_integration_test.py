# Copyright 2024 The SiliFuzz Authors.
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

import json
import os.path
import re
import subprocess

from absl.testing import absltest

from fuzzer.hashtest import hashtest_result_pb2


def get_data_dependency(name: str) -> str:
  return os.path.join(
      absltest.get_default_test_srcdir(),
      os.environ.get('TEST_WORKSPACE', ''),
      name,
  )


CURRENT_VERSION: str = '1.3.0'

HASHTEST_RUNNER_PATH = get_data_dependency('fuzzer/hashtest/hashtest_runner')

EXTRACT_JSON = re.compile(
    r'^BEGIN_JSON\n(.*?)\nEND_JSON$', re.DOTALL | re.MULTILINE
)


class HashtestRunnerTest(absltest.TestCase):

  def extract_json(self, stdout: str) -> dict[str, any]:
    m = EXTRACT_JSON.search(stdout)
    if m is None:
      self.fail(f'No JSON found in output: {stdout}')
    return json.loads(m.group(1))

  def check_json(self, data: dict[str, any]):
    # Check that the basic fields are present.
    for field, t in [
        ('hostname', str),
        ('platform', str),
        ('vector_width', int),
        ('mask_width', int),
        ('version', str),
        ('seed', int),
        ('threads', int),
        ('test_started', int),
        ('test_ended', int),
        ('stats', dict),
        ('cpus_hit', list),
    ]:
      self.assertIn(field, data)
      self.assertIsInstance(data[field], t)

  def run_hashtest(self, args: list[str], expected_returncode: int) -> str:
    """Run the hashtest runner with the given args and return the output."""
    cmd = [HASHTEST_RUNNER_PATH] + args
    result = subprocess.run(
        cmd,
        capture_output=True,
        check=False,
    )
    self.assertEqual(
        result.returncode,
        expected_returncode,
    )
    return result.stdout

  def run_hashtest_parse_json(
      self, args: list[str], expected_returncode: int
  ) -> dict[str, any]:
    """Run the hashtest runner with the given args and return the JSON in the output."""
    stdout = self.run_hashtest(args, expected_returncode)
    stdout = stdout.decode('utf-8')
    return self.extract_json(stdout)

  def run_hashtest_parse_proto(
      self, args: list[str], expected_returncode: int
  ) -> hashtest_result_pb2.HashTestResult:
    """Run the hashtest runner with the given args and return the Proto output."""
    stdout = self.run_hashtest(args, expected_returncode)
    res = hashtest_result_pb2.HashTestResult()
    res.ParseFromString(stdout)
    return res

  def test_json(self):
    seed = 123
    data = self.run_hashtest_parse_json(
        [
            '--seed',
            str(seed),
            '--tests',
            '10000',
            '--inputs',
            '5',
            '--repeat',
            '5',
            '--time',
            '2s',
            '-j',
            '2',
        ],
        0,
    )
    self.check_json(data)
    self.assertEqual(data['seed'], seed)

  def test_proto(self):
    seed = 456
    # Regression test - run for more than 10s so that if the "heartbeat" prints
    # anything in --print_proto mode, the proto will fail to parse.
    data = self.run_hashtest_parse_proto(
        [
            '--seed',
            str(seed),
            '--time',
            '30s',
            '-j',
            '2',
            '--print_proto',
        ],
        0,
    )

    self.assertNotEmpty(data.hostname)
    self.assertNotEmpty(data.platform)
    self.assertEqual(data.version, CURRENT_VERSION)

    self.assertEqual(data.status, hashtest_result_pb2.HashTestResult.OK)

    self.assertGreaterEqual(data.testing_started.seconds, 0)
    self.assertGreaterEqual(data.testing_ended.seconds, 0)
    self.assertGreaterEqual(
        data.testing_ended.seconds, data.testing_started.seconds
    )

    self.assertGreaterEqual(data.tests_run, 0)
    self.assertEqual(data.tests_failed, 0)

    self.assertNotEmpty(data.tested_cpus)
    self.assertEmpty(data.suspected_cpus)

  def test_proto_bad_platform(self):
    seed = 789
    data = self.run_hashtest_parse_proto(
        [
            '--seed',
            str(seed),
            '--time',
            '2s',
            '--print_proto',
            '--platform',
            'NON-EXISTENT-PLATFORM',
        ],
        1,
    )

    self.assertNotEmpty(data.hostname)
    self.assertNotEmpty(data.platform)
    self.assertEqual(data.version, CURRENT_VERSION)

    self.assertEqual(
        data.status, hashtest_result_pb2.HashTestResult.PLATFORM_NOT_SUPPORTED
    )

    self.assertGreaterEqual(data.testing_started.seconds, 0)
    self.assertGreaterEqual(data.testing_ended.seconds, 0)
    self.assertGreaterEqual(
        data.testing_ended.seconds, data.testing_started.seconds
    )

    self.assertEqual(data.tests_run, 0)
    self.assertEqual(data.tests_failed, 0)


if __name__ == '__main__':
  absltest.main()
