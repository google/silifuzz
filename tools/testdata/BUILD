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

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

genrule(
    name = "test_relocatable_corpus",
    testonly = 1,
    outs = ["runnable_corpus-fake-platform-00000"],
    cmd = """$(location @silifuzz//snap/testing:snap_test_snaps_gen) --output_mode=relocatable_runner_corpus > $@""",
    exec_tools = ["@silifuzz//snap/testing:snap_test_snaps_gen"],
)
