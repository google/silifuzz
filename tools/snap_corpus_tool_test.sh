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

set -eu -o pipefail

function die() {
  echo "$@"
  exit 1
}

readonly TOOL="${TEST_SRCDIR}/silifuzz/tools/snap_corpus_tool"
readonly CORPUS="${TEST_SRCDIR}/silifuzz/snap/testing/test_corpus"

function snap_corpus_tool_test() {
 "${TOOL}" list_snaps "${CORPUS}" 2>&1 | grep -q 'Total 23' \
   || die "snap_corpus_tool test failed"
}

function extract_test() {
  OUTPUT="$(mktemp)"
  ID=kEndsAsExpected
  "${TOOL}" extract "${CORPUS}" ${ID} "${OUTPUT}" 2>&1 \
    | grep -q 'Wrote snap to' \
    || die "extract test failed"
  rm -f "${OUTPUT}"
}

function extract_code_address_test() {
  OUTPUT="$(mktemp)"
  CODE_ADDRESS=0x12355000
  "${TOOL}" extract_code_address "${CORPUS}" ${CODE_ADDRESS} \
    "${OUTPUT}" 2>&1 | grep -q 'Wrote snap to' \
    || die "extract_code_address test failed"
  rm -f "${OUTPUT}"
}

snap_corpus_tool_test
extract_test
extract_code_address_test

echo "PASS"
