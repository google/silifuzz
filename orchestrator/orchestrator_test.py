"""Integrations tests for SiliFuzz orchestrator."""

import lzma
import os
import re
import struct
import subprocess
import time
from typing import Iterator

import absl.logging
from absl.testing import absltest
from absl.testing import parameterized

from silifuzz.proto import binary_log_entry_pb2 as bpb2


def get_data_dependency(name: str) -> str:
  return os.path.join(
      absltest.get_default_test_srcdir(),
      name,
  )


_ORCHESTRATOR_PATH = get_data_dependency(
    'silifuzz/orchestrator/silifuzz_orchestrator_main'
)

_RUNNER_PATH = get_data_dependency('silifuzz/orchestrator/test_runner')

_ENDS_AS_EXPECTED_CORPUS_PATH = get_data_dependency(
    'silifuzz/snap/testing/ends_as_expected_corpus'
)

_RUNAWAY_CORPUS_PATH = get_data_dependency(
    'silifuzz/snap/testing/runaway_corpus'
)


class OrchestratorTest(parameterized.TestCase):
  _FAKE_CORPUS: list[str] = []
  _CORPUS_METADATA_FILE: str = ''

  @classmethod
  def setUpClass(cls):
    super(OrchestratorTest, cls).setUpClass()
    corpus_paths = [_ENDS_AS_EXPECTED_CORPUS_PATH, _RUNAWAY_CORPUS_PATH]
    for i, original_path in enumerate(corpus_paths):
      with open(original_path, 'rb') as f:
        contents = f.read()
      # Compress one corpus only. The orchestrator can load
      # both corpora with and without compression.
      is_compressed = i > 0
      suffix = '.xz' if is_compressed else ''
      path = os.path.join(
          absltest.get_default_test_tmpdir(),
          f'{os.path.basename(original_path)}{suffix}',
      )
      with open(path, 'wb') as f:
        if is_compressed:
          f.write(lzma.compress(contents))
        else:
          f.write(contents)
      cls._FAKE_CORPUS.append(path)
    cls._CORPUS_METADATA_FILE = os.path.join(
        absltest.get_default_test_tmpdir(), 'corpus_metadata'
    )
    with open(cls._CORPUS_METADATA_FILE, 'w') as f:
      f.write('version: "corpus_version"')

  def _popen_args(
      self,
      test_dummy_commands: list[str],
      duration_sec: int,
      max_cpus: int,
      shard_list_file: str,
      extra_args: list[str],
  ) -> dict[str, object]:
    args = (
        [
            _ORCHESTRATOR_PATH,
            '--orchestrator_version=my_version',
            f'--corpus_metadata_file={self._CORPUS_METADATA_FILE}',
            f'--runner={_RUNNER_PATH}',
            f'--shard_list_file={shard_list_file}',
            '--stderrthreshold=0',
            f'--duration={duration_sec}s',
            f'--max_cpus={max_cpus}',
        ]
        + (extra_args or [])
        + ['--']
        + (test_dummy_commands or [])
    )
    absl.logging.info(' '.join(args))
    pass_fds = []
    # Figure out the value of --binary_log_fd. It's either this or plumbing
    # Popen **kwargs all the way to assertOrchestratorExitCode()
    for f, fn in zip(args, args[1:]):
      if f == '--binary_log_fd':
        pass_fds.append(int(fn))
    return dict(args=args, stderr=subprocess.PIPE, pass_fds=pass_fds)

  def _run(self, *args, **kwargs):
    popen_args = self._popen_args(*args, **kwargs)
    proc = subprocess.Popen(**popen_args)
    # The timeout value is determined by the max polling interval in the
    # orchestrator which is currently 10s.
    _, stderr = proc.communicate(timeout=kwargs['duration_sec'] + 10)
    return stderr.decode('utf-8').split('\n'), proc.returncode

  def assertStrSeqContainsAll(self, seq: list[str], regexs: list[str]):
    """Assert that the regular expression matches any string in `seq`."""

    for r in regexs:
      for s in seq:
        if re.search(r, s):
          break
      else:
        self.fail(f'Did not find "{r}" in\n========\n' + '\n'.join(seq))

  def run_orchestrator(
      self,
      test_dummy_commands: list[str],
      duration_sec: int = 3,
      max_cpus: int = 1,
      multicorpus: bool = False,
      extra_args: list[str] = None,
      scrape_binary_log: bool = False,
  ) -> (list[str], int, Iterator[bpb2.BinaryLogEntry]):
    corpus_files = [self._FAKE_CORPUS[0]]
    if multicorpus:
      corpus_files.append(self._FAKE_CORPUS[1])
    shard_list_file = self.create_tempfile(content='\n'.join(corpus_files))

    read_fd, write_fd = None, None
    if scrape_binary_log:
      (read_fd, write_fd) = os.pipe()
      extra_args = extra_args or []
      extra_args.extend(['--binary_log_fd', str(write_fd)])

    (err_log, returncode) = self._run(
        duration_sec=duration_sec,
        max_cpus=max_cpus,
        shard_list_file=shard_list_file.full_path,
        extra_args=extra_args,
        test_dummy_commands=test_dummy_commands,
    )
    bin_log = None
    if scrape_binary_log:
      os.close(write_fd)
      bin_log = os.read(read_fd, 4096)
      os.close(read_fd)
    return (err_log, returncode, self._parse_binary_log(bin_log))

  def test_basic(self):
    (err_log, returncode, _) = self.run_orchestrator(
        ['short_output', 'short_loop'],
        duration_sec=10,
    )
    self.assertEqual(returncode, 0)
    self.assertStrSeqContainsAll(
        err_log,
        ['T0 started', 'ShortOutput', 'T0.*exit_status: ok', 'T0 stopped'],
    )

  def test_multicpu(self):
    (err_log, returncode, _) = self.run_orchestrator(
        ['short_output'], max_cpus=3
    )
    self.assertEqual(returncode, 0)
    self.assertStrSeqContainsAll(
        err_log,
        [
            'T0 started',
            'ShortOutput',
            'T0.*exit_status: ok',
            'T1.*exit_status: ok',
            'T2.*exit_status: ok',
        ],
    )

  def test_exit7(self):
    (err_log, returncode, _) = self.run_orchestrator(['short_loop', 'exit7'])
    self.assertEqual(returncode, 0)
    self.assertStrSeqContainsAll(
        err_log,
        [
            'T0.*exit_status: internal_error',
        ],
    )

  def test_timeout(self):
    # If you change --timeout=2 to something else, also change test_runner.cc.
    (err_log, returncode, _) = self.run_orchestrator(
        ['--timeout=2', 'infinite_loop']
    )
    self.assertEqual(returncode, 0)
    self.assertStrSeqContainsAll(
        err_log,
        [
            'T0.*exit_status: internal_error',
        ],
    )

  def test_sequential_mode(self):
    (err_log, returncode, _) = self.run_orchestrator(
        [], extra_args=['--sequential_mode'], multicorpus=True
    )
    self.assertEqual(returncode, 0)
    self.assertStrSeqContainsAll(
        err_log,
        [
            'TEST RUNNER sequential_mode',
            'T0 Reached end of stream in sequential mode',
        ],
    )

  def test_multiple_corpora(self):
    # Check that the uncompressed contents of both fake corpora are present.
    (err_log, returncode, _) = self.run_orchestrator(
        ['print_first_snap_id'],
        extra_args=['--sequential_mode'],
        multicorpus=True,
    )
    self.assertEqual(returncode, 0)
    self.assertStrSeqContainsAll(
        err_log,
        [
            'kEndsAsExpected',
            'kRunaway',
        ],
    )

  def test_snap_failure(self):
    (err_log, returncode, _) = self.run_orchestrator(
        ['snap_fail'], extra_args=['--enable_v1_compat_logging']
    )
    self.assertEqual(
        returncode, 1, msg='Expected EXIT_FAILURE ' + '\n'.join(err_log)
    )
    latest_entry = self._parse_v1_log(err_log)
    self.assertGreater(
        int(latest_entry['issues_detected']),
        50,  # a fairly arbitrary number of failures expected in 3 sec.
        msg=(
            'Expected at least a 50 failures to be detected within the'
            ' duration of the test'
        ),
    )
    self.assertStrSeqContainsAll(
        err_log,
        [
            'snap_fail: my_snap',
            'exit_status: snap_fail',
            'Silifuzz detected issue on CPU.*running snapshot my_snap',
        ],
    )

  # Returns the latest v1-style log entry as a dictionary
  def _parse_v1_log(self, lines):
    logs = [
        line.split(':')[1]
        for line in lines
        if line.startswith('Silifuzz Checker Result:')
    ]
    if not logs:
      return {}
    r = {}
    for kv in logs[-1].strip('{}').split(','):
      (k, v) = kv.split('=')
      r[k.strip()] = v.strip()
    return r

  def test_failfast(self):
    (err_log, returncode, _) = self.run_orchestrator(
        ['snap_fail'],
        extra_args=['--enable_v1_compat_logging', '--fail_after_n_errors=2'],
    )
    self.assertEqual(returncode, 1)
    latest_entry = self._parse_v1_log(err_log)
    # The orchestrator does not fail immediately and can keep running for a
    # while after the first failure. The test allows up to 4 for the fail-fast
    # logic to kick in.
    self.assertLessEqual(int(latest_entry['issues_detected']), 4)
    self.assertGreaterEqual(int(latest_entry['issues_detected']), 2)

  def test_v1_logging(self):
    (err_log, _, _) = self.run_orchestrator(
        ['long_loop'],
        duration_sec=10,
        extra_args=['--enable_v1_compat_logging'],
    )

    def _parse_secs(s):
      return int(s.rstrip('s'))

    latest_entry = self._parse_v1_log(err_log)
    self.assertGreater(int(latest_entry['num_cores']), 0)
    self.assertEqual(int(latest_entry['issues_detected']), 0)
    self.assertGreater(_parse_secs(latest_entry['elapsed_time']), 0)
    self.assertGreater(_parse_secs(latest_entry['user_time']), 0)

  def test_duration(self):
    (err_log, returncode, _) = self.run_orchestrator(['sleep100'])
    self.assertEqual(returncode, 0)
    self.assertStrSeqContainsAll(
        err_log,
        [
            'corpus: ends_as_expected_corpus',
            'Runner killed by signal 14',
            'exit_status: internal_error',
        ],
    )

  def test_checksum_mismatch(self):
    (err_log, returncode, bin_log) = self.run_orchestrator(
        ['checksum_mismatch'],
        extra_args=[
            '--sequential_mode',
        ],
        scrape_binary_log=True,
    )
    self.assertEqual(
        returncode, 1, msg='Expected EXIT_FAILURE ' + '\n'.join(err_log)
    )
    self.assertStrSeqContainsAll(
        err_log,
        [
            'Snapshot checksum mismatch',
        ],
    )
    snap_failure = None
    for e in bin_log:
      if e.HasField('snapshot_execution_result'):
        snap_failure = e.snapshot_execution_result
    self.assertIsNotNone(
        snap_failure, msg='Expected a SnapshotExecutionResult'
    )
    # Mirrors the corresponding enum value in snapshot_enums.h without
    # introducing a dependency on that file or the proto.
    runner_postfailure_checksum_status_mismatch = 2
    self.assertEqual(
        snap_failure.postfailure_checksum_status,
        runner_postfailure_checksum_status_mismatch,
    )

  def test_no_execution_result(self):
    (err_log, returncode, _) = self.run_orchestrator(['no_execution_result'])
    self.assertEqual(returncode, 0)
    self.assertStrSeqContainsAll(
        err_log,
        [
            'Missing required execution_result',
        ],
    )

  def test_mmap_failed(self):
    (err_log, returncode, _) = self.run_orchestrator(['mmap_failed'])
    self.assertEqual(
        returncode,
        0,
        msg=(
            'Expected no failure from the orchestrator if the runner fails to'
            ' map memory'
        ),
    )
    self.assertStrSeqContainsAll(
        err_log,
        [
            'failed to map memory',
        ],
    )

  def test_watchdog(self):
    (err_log, returncode, _) = self.run_orchestrator(
        ['ignore_alarm', 'sleep100'],
        extra_args=['--watchdog_allowed_overrun=1s'],
    )
    self.assertEqual(returncode, 0)
    self.assertStrSeqContainsAll(
        err_log,
        [
            'Terminated by watchdog',
        ],
    )

  def _parse_binary_log(self, data):
    """A quick parser for the binary log format. See binary_log_channel.h."""
    while data:
      l = struct.unpack('<Q', data[:8])[0]
      e = bpb2.BinaryLogEntry()
      e.ParseFromString(data[8 : 8 + l])
      yield e
      data = data[8 + l :]

  def test_binary_logging(self):
    (err_log, returncode, bin_log) = self.run_orchestrator(
        ['snap_fail'],
        extra_args=[
            '--sequential_mode',
            '--log_session_summary_probability=1',
        ],
        scrape_binary_log=True,
    )
    self.assertEqual(returncode, 1)
    self.assertStrSeqContainsAll(
        err_log,
        [
            'snap_fail: my_snap',
            'exit_status: snap_fail',
        ],
    )
    session_summary = None
    session_start = None
    for e in bin_log:
      if e.HasField('session_summary'):
        self.assertIsNone(session_summary, msg='Expected exactly 1')
        session_summary = e.session_summary
      if e.HasField('session_start'):
        self.assertIsNone(session_start, msg='Expected exactly 1')
        session_start = e.session_start
    self.assertIsNotNone(
        session_summary,
        msg='SessionSummary was not set in any log entry, expected exactly 1',
    )
    self.assertIsNotNone(
        session_start,
        msg='SessionStart was not set in any log entry, expected exactly 1',
    )

    # the value is sampled by the orchestrator and it's hard to reliably
    # catch non-zero value in the test setting so we avoid testing the actual
    # value.
    # self.assertTrue(session_summary.resource_usage.HasField('max_rss_kb'))

  def test_binary_logging_bad_fd(self):
    (err_log, returncode, _) = self.run_orchestrator(
        ['snap_fail'],
        extra_args=[
            '--sequential_mode',
            '--log_session_summary_probability=1',
            '--binary_log_fd=10000',
        ],
    )
    self.assertEqual(returncode, 1)
    self.assertStrSeqContainsAll(
        err_log,
        [
            'Binary logging failed',
            'Bad file descriptor',
        ],
    )

  def test_rlimit_fsize(self):
    (err_log, returncode, _) = self.run_orchestrator(
        ['long_output'], extra_args=['--sequential_mode']
    )
    self.assertEqual(returncode, 0)
    self.assertStrSeqContainsAll(
        err_log,
        [
            'exit_status: internal_error',
        ],
    )

  def test_sigint(self):
    shard_list_file = self.create_tempfile(content=self._FAKE_CORPUS[0])
    popen_args = self._popen_args(
        test_dummy_commands=['sleep100'],
        max_cpus=1,
        shard_list_file=shard_list_file.full_path,
        duration_sec=3600,
        extra_args=['--sequential_mode'],
    )
    # start_new_session ensures that the orchestrator process is in its own
    # process group so that we can killpg() it later.
    with subprocess.Popen(start_new_session=True, **popen_args) as proc:
      time.sleep(5)
      # Send SIGINT to the orchestator's process group. This simulates ^C
      # behavior.
      os.killpg(proc.pid, 2)
      # NOTE: the communicate() interface used in all other tests takes care of
      # buffering the stdout/stderr in memory. This test relies on the fact
      # that the child process output will fit into the default kernel buffer.
      proc_err = proc.stderr.read(4096)
      self.assertIn('SIGINT/SIGALRM caught', proc_err.decode('utf-8'))
    self.assertEqual(proc.returncode, 0)

  def test_aslr_off(self):
    (err_log, returncode, _) = self.run_orchestrator(['print_main_address'])
    self.assertEqual(returncode, 0)
    matching_lines = [x for x in err_log if x.startswith('main:')]
    # Verify there are at least 2 "main:$addr" lines the test dummy prints and
    # they are all the same b/c ASLR is off.
    self.assertGreater(len(matching_lines), 1)
    self.assertSetEqual(set(matching_lines), {matching_lines[0]})

  @parameterized.named_parameters(
      dict(
          testcase_name='best_effort_oom',
          memory_limit_mb=512,
          expected_return_code=1,
          expected_cpus=None,
          expected_shards=None,
          max_cpus=16,
      ),
      dict(
          testcase_name='best_effort_capped',
          memory_limit_mb=512 * 2 + 1,
          expected_return_code=0,
          expected_cpus=2,
          expected_shards=1,
          max_cpus=16,
      ),
      dict(
          testcase_name='best_effort_capped_2',
          memory_limit_mb=512 * 2 + 2,
          expected_return_code=0,
          expected_cpus=2,
          expected_shards=2,
          max_cpus=0,
      ),
      dict(
          testcase_name='best_effort_not_capped',
          memory_limit_mb=512 * 2 + 9999,
          expected_return_code=0,
          expected_cpus=2,
          expected_shards=2,
          max_cpus=2,
      ),
  )
  def test_best_effort(
      self,
      memory_limit_mb,
      expected_return_code,
      expected_cpus,
      expected_shards,
      max_cpus,
  ):
    (err_log, returncode, _) = self.run_orchestrator(
        ['short_output', 'short_loop'],
        max_cpus=max_cpus,
        extra_args=[f'--limit_memory_usage_mb={memory_limit_mb}'],
        multicorpus=True,
    )
    self.assertEqual(returncode, expected_return_code)
    if expected_return_code != 0:
      return

    # Verify that the number of CPUs assigned to threads is equal to the
    # number of total CPUs.
    scheduled_cpus = 0
    total_cpus = None
    for line in err_log:
      m = re.search(r'(\d+) CPUs are assigned to T\d+', line)
      if m:
        scheduled_cpus += int(m.group(1))
        continue
      m = re.search(r'AVAIL MEM:.+CPUS: (\d+)', line)
      if m:
        total_cpus = int(m.group(1))
        continue
    self.assertEqual(total_cpus, scheduled_cpus)
    self.assertStrSeqContainsAll(
        err_log,
        [
            f'We can schedule {min(expected_cpus, total_cpus)}/'
            + r'\d+ runners',
            f'we can fit {expected_shards} of 2',
        ],
    )

  def test_large_max_cpus_flag(self):
    (err_log, returncode, _) = self.run_orchestrator(
        ['short_output', 'short_loop'],
        max_cpus=10000,
        extra_args=[f'--limit_memory_usage_mb={512 * 10000 + 3}'],
        multicorpus=True,
    )
    self.assertEqual(returncode, 0)

    # Verify that the number of CPUs assigned to threads is equal to the
    # number of total CPUs.
    scheduled_cpus = 0
    total_cpus = None
    for line in err_log:
      m = re.search(r'(\d+) CPUs are assigned to T\d+', line)
      if m:
        scheduled_cpus += int(m.group(1))
        continue
      m = re.search(r'AVAIL MEM:.+CPUS: (\d+)', line)
      if m:
        total_cpus = int(m.group(1))
        continue
    self.assertEqual(total_cpus, scheduled_cpus)


if __name__ == '__main__':
  absltest.main()
