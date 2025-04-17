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
# Test that runner_main_nolibc binary does not have any global static
# initializer. This is done by checking the absence of .init_array section
# in the binary.

set -eu -o pipefail

RUNNER_BINARY="${TEST_SRCDIR}/${TEST_WORKSPACE}/runner/reading_runner_main_nolibc"
readonly RUNNER_BINARY

# Make sure the file exists
[[ -f "${RUNNER_BINARY}" ]]

# There should not be a .init_array section.
if readelf -S "${RUNNER_BINARY}" | grep -q ".init_array"; then
  echo "Found .init_array section in the binary"
  exit 1
fi

echo "PASS"
