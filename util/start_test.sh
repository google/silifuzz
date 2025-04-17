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

# Test helper
START_TEST_HELPER="${TEST_SRCDIR}/${TEST_WORKSPACE}/util/start_test_helper_nolibc"

die() {
  echo "$@"
  exit 1
}

code=0
"${START_TEST_HELPER}" || code="$?"
case "${code}" in
  0)
    # no error.
    ;;
  1)
    die "Stack misaligned at main()"
    ;;
  *)
    die "Helper failed with unknown exit code ${code}"
    ;;
esac

"${START_TEST_HELPER}" 42 || code="$?"
[[ "$code" -eq 42 ]] || die "Failed to return argv[1]"

echo "PASS"
