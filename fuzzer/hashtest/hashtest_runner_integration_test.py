#!/usr/bin/env python3

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


def get_data_dependency(name: str) -> str:
  return os.path.join(
      absltest.get_default_test_srcdir(),
      name,
  )


HASHTEST_RUNNER_PATH = get_data_dependency(
    'silifuzz/fuzzer/hashtest/hashtest_runner'
)

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

  def run_hashtest(self, args: list[str]) -> str:
    """Run the hashtest runner with the given args and return the output."""
    cmd = [HASHTEST_RUNNER_PATH] + args
    result = subprocess.run(
        cmd,
        capture_output=True,
        check=False,
    )
    self.assertEqual(
        result.returncode,
        0,
        f'Hashtest runner failed with code {result.returncode}',
    )
    stdout = result.stdout.decode('utf-8')
    return self.extract_json(stdout)

  def test_standard(self):
    seed = 123
    data = self.run_hashtest([
        '--seed',
        str(seed),
        '--tests',
        '10000',
        '--inputs',
        '5',
        '--repeat',
        '5',
    ])
    self.check_json(data)
    self.assertEqual(data['seed'], seed)

  def test_timed(self):
    seed = 456
    data = self.run_hashtest([
        '--seed',
        str(seed),
        '--tests',
        '10000',
        '--inputs',
        '5',
        '--repeat',
        '5',
        '--time',
        '1s',
    ])
    self.check_json(data)
    self.assertEqual(data['seed'], seed)


if __name__ == '__main__':
  absltest.main()
