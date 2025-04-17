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

#!/bin/bash

set -eu
set -o pipefail

GENERATOR="${TEST_SRCDIR}/${TEST_WORKSPACE}/fuzzer/hashtest/hashtest_generator"
readonly GENERATOR

# Make sure we can generate snapshots for various x86 platforms.
${GENERATOR} --platform=intel-broadwell -n 100 --seed 1
${GENERATOR} --platform=intel-skylake -n 100 --seed 2
${GENERATOR} --platform=intel-sapphirerapids -n 100 --seed 3

echo "PASS"
