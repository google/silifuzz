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

"""Shared constants."""

# Formatted as silifuzz::PlatformId's ToString()
SILIFUZZ_PLATFORMS = [
    "intel-skylake",
    "intel-haswell",
    "intel-broadwell",
    "intel-cascadelake",
    "amd-rome",
    "amd-milan",
]

# The base address of the runner.  This is abitrary. We expect this to be
# unlikely to collide with snapshots due to the size of the user address space.
# There is also a run time check in the runner to verify that no collision happens.
SILIFUZZ_RUNNER_BASE_ADDRESS = "0x456700000000"
