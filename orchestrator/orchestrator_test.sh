# Copyright 2022 The SiliFuzz Authors.
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

#!/bin/bash
# Tests silifuzz-orchestrator.
# Works together with test-runner.
set -eu

source gbash.sh || exit 1
source module gbash_unit.sh

readonly ORC="${TEST_SRCDIR}/silifuzz/orchestrator/silifuzz_orchestrator_main"
readonly RUNNER="${TEST_SRCDIR}/silifuzz/orchestrator/test_runner"

# Shorthand for $ORC with flags.
function orc() {
  echo "${ORC}" --v=1 --alsologtostderr --duration=3s --runner="${RUNNER}" "$@"
  "${ORC}" --v=1 --alsologtostderr --duration=3s --runner="${RUNNER}" "$@"
}

readonly FAKE_CORPUS_1="${TEST_TMPDIR}/fake_corpus_1.xz"
readonly FAKE_CORPUS_2="${TEST_TMPDIR}/fake_corpus_2.xz"

# Create fake corpora. These are just zipped text files.
echo "Corpus One" | xz - > "${FAKE_CORPUS_1}"
echo "Corpus Two" | xz - > "${FAKE_CORPUS_2}"

function test::basic() {
  local result_file="$(mktemp)"
  EXPECT_SUCCEED "orc -max_cpus=1 "${FAKE_CORPUS_1}" -- short_output short_loop 2> "${result_file}""
  EXPECT_SUCCEED "grep -q 'T0 started' "${result_file}""
  EXPECT_SUCCEED "grep -q ShortOutput "${result_file}""
  EXPECT_SUCCEED "grep -q 'T0.*exit_status: ok' "${result_file}""
  EXPECT_SUCCEED "grep -q 'T0 stopped' "${result_file}""
  rm -f "${result_file}"
}

function test::multithreaded() {
  local result_file="$(mktemp)"
  EXPECT_SUCCEED "orc -max_cpus=3 "${FAKE_CORPUS_1}" -- short_output 2> "${result_file}""
  EXPECT_SUCCEED "grep -q 'T0 started' "${result_file}""
  EXPECT_SUCCEED "grep -q ShortOutput "${result_file}""
  EXPECT_SUCCEED "grep -q 'T0.*exit_status: ok' "${result_file}""
  EXPECT_SUCCEED "grep -q 'T1.*exit_status: ok' "${result_file}""
  EXPECT_SUCCEED "grep -q 'T1.*exit_status: ok' "${result_file}""
  rm -f "${result_file}"
}

function test::exit7() {
  local result_file="$(mktemp)"
  EXPECT_SUCCEED "orc -max_cpus=1 "${FAKE_CORPUS_1}" -- short_loop exit7 2> "${result_file}""
  EXPECT_SUCCEED "grep -q 'T0.*exit_status: internal_error' "${result_file}"" # Actual exit status for exit(7) is (7<<8)=1792.
  rm -f "${result_file}"
}

function test::timeout() {
  local result_file="$(mktemp)"
  # If you change --timeout=2 to something else, also change test-runner.cc.
  EXPECT_SUCCEED "orc -max_cpus=1 "${FAKE_CORPUS_1}" -- --timeout=2 infinite_loop 2> "${result_file}""
  EXPECT_SUCCEED "grep -q 'T0.*exit_status: internal_error' "${result_file}""
  rm -f "${result_file}"
}

function test::sequential_mode() {
  local result_file="$(mktemp)"
  EXPECT_SUCCEED "orc -max_cpus=1 --sequential_mode=True "${FAKE_CORPUS_1}" "${FAKE_CORPUS_2}" 2> "${result_file}""
  num_runners="$(grep 'TEST RUNNER sequential_mode' "${result_file}" | wc -l)"
  EXPECT_EQ "${num_runners}" 2
  EXPECT_SUCCEED "grep -q 'T0 Reached end of stream in sequential mode' "${result_file}""
  rm -f "${result_file}"
}

function test::multiple_corpora() {
  local result_file="$(mktemp)"
  EXPECT_SUCCEED "orc -max_cpus=1 "${FAKE_CORPUS_1}" "${FAKE_CORPUS_2}" -- print_first_line 2> "${result_file}""
  # Check that the uncompressed contents of both fake corpora are present.
  EXPECT_SUCCEED "grep -q 'Corpus One' "${result_file}""
  EXPECT_SUCCEED "grep -q 'Corpus Two' "${result_file}""
  rm -f "${result_file}"
}

function test::aslr_off() {
  local result_file="$(mktemp)"
  # Run with ASLR disabled (default).
  EXPECT_SUCCEED "orc -max_cpus=1 "${FAKE_CORPUS_1}" -- print_main_address 2> "${result_file}""
  # Many lines with main:
  EXPECT_GT "$(grep -o "main:.*" "${result_file}" | wc -l)" 1
  # But all lines are the same, i.e. ASLR is disabled
  EXPECT_EQ "$(grep -o "main:.*" "${result_file}" | uniq  | wc -l)" 1

  rm -f "${result_file}"
}

function test::rlimit_fsize() {
  local result_file="$(mktemp)"
  EXPECT_SUCCEED "orc -max_cpus=1 "${FAKE_CORPUS_1}" -- long_output 2> "${result_file}""
  # RLIMIT_FSIZE is set to 1Mb (1048576 bytes).
  # where 25 is SIGXFSZ caused by RLIMIT_FSIZE.
  EXPECT_SUCCEED "grep -q 'exit_status: internal_error' "${result_file}""
  rm -f "${result_file}"
}

function test::snap_failure() {
  local result_file="$(mktemp)"
  EXPECT_FAIL "orc -max_cpus=1 --enable_v1_compat_logging "${FAKE_CORPUS_1}" -- snap_fail 2> "${result_file}""
  EXPECT_SUCCEED "grep -q 'snap_fail: my_snap' "${result_file}""
  EXPECT_SUCCEED "grep -q 'exit_status: snap_fail' "${result_file}""
  EXPECT_SUCCEED "grep -q 'Silifuzz detected issue on CPU.*running snapshot my_snap' "${result_file}""
  rm -f "${result_file}"
}

function test::binary_logging() {
  local result_file="$(mktemp)"
  local BINARY_LOG="$(mktemp)"
  exec 3<> "${BINARY_LOG}"
  EXPECT_FAIL "orc -max_cpus=1 --binary_log_fd=3 "${FAKE_CORPUS_1}" -- snap_fail 2> "${result_file}""
  exec 3>&- # close fd 3
  EXPECT_FILE_NOT_EMPTY "${BINARY_LOG}"
  rm -f "${result_file}"
}

function test::duration() {
  local result_file="$(mktemp)"
  EXPECT_SUCCEED "orc -max_cpus=2 "${FAKE_CORPUS_1}" -- sleep100 2> "${result_file}""
  EXPECT_SUCCEED "grep -q 'exit_status: internal_error' "${result_file}""
  EXPECT_EQ "$(grep 'Runner killed by signal 14' "${result_file}" | wc -l)" 2
  rm -f "${result_file}"
}

gbash::unit::main "$@"
