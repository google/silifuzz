"""Integrations tests for SiliFuzz orchestrator."""

import lzma
import os
import re
import subprocess
import time

import absl.logging
from absl.testing import absltest


def get_data_dependency(name: str) -> str:
  return os.path.join(
      absltest.get_default_test_srcdir(),
      name)


_ORCHESTRATOR_PATH = get_data_dependency(
    'silifuzz/orchestrator/silifuzz_orchestrator_main')

_RUNNER_PATH = get_data_dependency('silifuzz/orchestrator/test_runner')


class OrchestratorTest(absltest.TestCase):

  _FAKE_CORPUS = []

  @classmethod
  def setUpClass(cls):
    super(OrchestratorTest, cls).setUpClass()
    temp_dir = absltest.get_default_test_tmpdir()
    corpus_contents = ['One', 'Two']
    for i, contents in enumerate(corpus_contents):
      # Compress one corpus only. The orchestrator can load
      # both corpora with and without compression.
      is_compressed = i > 0
      suffix = '.xz' if is_compressed else ''
      path = os.path.join(temp_dir, f'fake_corpus_{contents}{suffix}')
      with open(path, 'wb') as f:
        encoded = f'Corpus {contents}'.encode('ascii')
        if is_compressed:
          f.write(lzma.compress(encoded))
        else:
          f.write(encoded)
      cls._FAKE_CORPUS.append(path)

  def _popen_args(
      self,
      test_dummy_commands: list[str],
      duration_sec: int,
      max_cpus: int,
      corpus_files: list[str],
      extra_args: list[str],
  ) -> dict[str, object]:
    args = [
        _ORCHESTRATOR_PATH,
        '--runner',
        _RUNNER_PATH,
        '--stderrthreshold=0',
        f'--duration={duration_sec}s',
        f'--max_cpus={max_cpus}',
    ] + (extra_args or []) + corpus_files + ['--'] + (
        test_dummy_commands or [])
    absl.logging.info(' '.join(args))
    pass_fds = []
    # Figure out the value of --binary_log_fd. It's either this or plumbing
    # Popen **kwargs all the way to assertOrchestratorExitCode()
    for (f, fn) in zip(args, args[1:]):
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

  def run_orchestrator(self,
                       test_dummy_commands: list[str],
                       duration_sec: int = 3,
                       max_cpus: int = 1,
                       multicorpus: bool = False,
                       extra_args: list[str] = None) -> (list[str], int):
    corpus_files = [self._FAKE_CORPUS[0]]
    if multicorpus:
      corpus_files.append(self._FAKE_CORPUS[1])
    (err_log, returncode) = self._run(
        duration_sec=duration_sec,
        max_cpus=max_cpus,
        corpus_files=corpus_files,
        extra_args=extra_args,
        test_dummy_commands=test_dummy_commands)
    return (err_log, returncode)

  def test_basic(self):
    (err_log,
     returncode) = self.run_orchestrator(['short_output', 'short_loop'])
    self.assertEqual(returncode, 0)
    self.assertStrSeqContainsAll(
        err_log,
        ['T0 started', 'ShortOutput', 'T0.*exit_status: ok', 'T0 stopped'])

  def test_multicpu(self):
    (err_log, returncode) = self.run_orchestrator(['short_output'], max_cpus=3)
    self.assertEqual(returncode, 0)
    self.assertStrSeqContainsAll(err_log, [
        'T0 started',
        'ShortOutput',
        'T0.*exit_status: ok',
        'T1.*exit_status: ok',
        'T2.*exit_status: ok',
    ])

  def test_exit7(self):
    (err_log, returncode) = self.run_orchestrator(['short_loop', 'exit7'])
    self.assertEqual(returncode, 0)
    self.assertStrSeqContainsAll(err_log, [
        'T0.*exit_status: internal_error',
    ])

  def test_timeout(self):
    # If you change --timeout=2 to something else, also change test_runner.cc.
    (err_log,
     returncode) = self.run_orchestrator(['--timeout=2', 'infinite_loop'])
    self.assertEqual(returncode, 0)
    self.assertStrSeqContainsAll(err_log, [
        'T0.*exit_status: internal_error',
    ])

  def test_sequential_mode(self):
    (err_log,
     returncode) = self.run_orchestrator([],
                                         extra_args=['--sequential_mode'],
                                         multicorpus=True)
    self.assertEqual(returncode, 0)
    self.assertStrSeqContainsAll(err_log, [
        'TEST RUNNER sequential_mode',
        'T0 Reached end of stream in sequential mode',
    ])

  def test_multiple_corpora(self):
    # Check that the uncompressed contents of both fake corpora are present.
    (err_log,
     returncode) = self.run_orchestrator(['print_first_line'],
                                         extra_args=['--sequential_mode'],
                                         multicorpus=True)
    self.assertEqual(returncode, 0)
    self.assertStrSeqContainsAll(err_log, [
        'Corpus One',
        'Corpus Two',
    ])

  def test_snap_failure(self):
    (err_log, returncode) = self.run_orchestrator(
        ['snap_fail'], extra_args=['--enable_v1_compat_logging'])
    self.assertEqual(returncode, 1)
    self.assertStrSeqContainsAll(err_log, [
        'snap_fail: my_snap', 'exit_status: snap_fail',
        'Silifuzz detected issue on CPU.*running snapshot my_snap'
    ])

  def test_duration(self):
    (err_log, returncode) = self.run_orchestrator(['sleep100'])
    self.assertEqual(returncode, 0)
    self.assertStrSeqContainsAll(err_log, [
        'exit_status: internal_error',
        'Runner killed by signal 14',
    ])

  def test_watchdog(self):
    (err_log, returncode) = self.run_orchestrator(
        ['ignore_alarm', 'sleep100'],
        extra_args=['--watchdog_allowed_overrun=1s'])
    self.assertEqual(returncode, 0)
    self.assertStrSeqContainsAll(err_log, [
        'Terminated by watchdog',
    ])

  def test_binary_logging(self):
    (read_fd, write_fd) = os.pipe()
    (err_log, returncode) = self.run_orchestrator(
        ['snap_fail'],
        extra_args=['--sequential_mode', '--binary_log_fd',
                    str(write_fd)],
    )
    self.assertEqual(returncode, 1)
    self.assertStrSeqContainsAll(err_log, [
        'snap_fail: my_snap',
        'exit_status: snap_fail',
    ])
    os.close(write_fd)
    bin_log = os.read(read_fd, 4096)
    os.close(read_fd)
    # TODO(ksteuck): Inspect the contents.
    self.assertNotEmpty(bin_log)

  def test_rlimit_fsize(self):
    (err_log,
     returncode) = self.run_orchestrator(['long_output'],
                                         extra_args=['--sequential_mode'])
    self.assertEqual(returncode, 0)
    self.assertStrSeqContainsAll(err_log, [
        'exit_status: internal_error',
    ])

  def test_sigint(self):
    popen_args = self._popen_args(
        test_dummy_commands=['sleep100'],
        max_cpus=1,
        corpus_files=[self._FAKE_CORPUS[0]],
        duration_sec=3600,
        extra_args=['--sequential_mode'])
    # start_new_session ensures that the orchestrator process is in its own
    # process group so that we can killpg() it later.
    with subprocess.Popen(start_new_session=True, **popen_args) as proc:
      time.sleep(5)
      # Send SIGINT to the orchestator's process group. This similates ^C
      # behavior.
      os.killpg(proc.pid, 2)
      # NOTE: the communicate() interface used in all other tests takes care of
      # buffering the stdout/stderr in memory. This test relies on the fact
      # that the child process output will fit into the default kernel buffer.
      proc_err = proc.stderr.read(4096)
      self.assertIn('SIGINT/SIGALRM caught', proc_err.decode('utf-8'))
    self.assertEqual(proc.returncode, 0)

  def test_aslr_off(self):
    (err_log, returncode) = self.run_orchestrator(['print_main_address'])
    self.assertEqual(returncode, 0)
    matching_lines = [x for x in err_log if x.startswith('main:')]
    # Verify there are at least 2 "main:$addr" lines the test dummy prints and
    # they are all the same b/c ASLR is off.
    self.assertGreater(len(matching_lines), 1)
    self.assertSetEqual(set(matching_lines), {matching_lines[0]})


if __name__ == '__main__':
  absltest.main()
