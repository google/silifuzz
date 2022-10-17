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

set -eu

function die() {
  echo "$@"
  exit 1
}

# Find input files
TOOL="${TEST_SRCDIR}/silifuzz/tools/fuzz_filter_tool"
readonly TOOL

# Rewritable cases
echo -n -e "\x90" | "${TOOL}" /dev/stdin || die "Failed in NOP"
echo -n -e "\xEB\x10" | "${TOOL}" /dev/stdin || die "Failed in JMP .+0x10"
echo -n -e "\xCC" | "${TOOL}" /dev/stdin || die "Failed in INT3"

# Unrewritable cases
# Syscalls are not allowed and are not fixed by MakerV2
echo -n -e "\xCD\x80" | "${TOOL}" /dev/stdin && die "Failed in INT 80"
echo -n -e "\x0F\x05" | "${TOOL}" /dev/stdin && die "Failed in SYSCALL"
echo -n -e "\x48\x31\xC0\x48\x31\xFF\x0F\x05" | "${TOOL}" /dev/stdin && die "Failed in blocking SYSCALL (read(2) from stdin)"

echo -n -e "\xF1" | "${TOOL}" /dev/stdin && die "Failed in INT1"
echo -n -e "\xCD\x03" | "${TOOL}" /dev/stdin && die "Failed in INT 3"
echo -n -e "\x0F\x0B" | "${TOOL}" /dev/stdin && die "Failed in UD2"
echo -n -e "\xED" | "${TOOL}" /dev/stdin && die "Failed in IN"
echo -n -e "\xEF" | "${TOOL}" /dev/stdin && die "Failed in OUT"
echo -n -e "\x0F\x31" | "${TOOL}" /dev/stdin && die "Failed in RDTSC"
echo -n -e "\x0F\xA2" | "${TOOL}" /dev/stdin && die "Failed in CPUID"
echo -n -e "\x0F\x00\xC0" | "${TOOL}" /dev/stdin && die "Failed in SLDT"
echo -n -e "\x48\x89\xe0\x48\xff\xc8\x30\xc0\xf0\xff\x40\xff" \
  | "${TOOL}" /dev/stdin && die "Failed in INC_LOCK"

echo "PASS"
