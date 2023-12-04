# Copyright 2023 The SiliFuzz Authors.
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

licenses(["notice"])

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "program_mutator",
    srcs = [
        "program.cc",
        "program_x86_64.cc",
    ],
    hdrs = [
        "program.h",
        "program_arch.h",
    ],
    deps = [
        "@silifuzz//instruction:xed_util",
        "@com_google_absl//absl/log:check",
        "@libxed//:xed",
    ],
)

cc_test(
    name = "program_mutator_test",
    size = "medium",
    srcs = ["program_mutator_test.cc"],
    deps = [
        ":program_mutator",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "program_mutator_fuzz_test",
    srcs = ["program_mutator_fuzz_test.cc"],
    deps = [
        ":program_mutator",
        "@com_google_fuzztest//fuzztest",
        "@com_google_googletest//:gtest_main",
    ],
)
