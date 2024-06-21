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

licenses(["notice"])

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "hashtest_generator_lib",
    srcs = [
        "candidate.cc",
        "debugging.cc",
        "prefilter.cc",
        "register_info.cc",
        "xed_operand_util.cc",
    ],
    hdrs = [
        "candidate.h",
        "debugging.h",
        "prefilter.h",
        "rand_util.h",
        "register_info.h",
        "xed_operand_util.h",
    ],
    deps = [
        "@silifuzz//instruction:xed_util",
        "@silifuzz//util:checks",
        "@com_google_absl//absl/base:core_headers",
        "@libxed//:xed",
    ],
)

cc_test(
    name = "hashtest_generator_test",
    srcs = [
        "hashtest_generator_test.cc",
    ],
    deps = [
        ":hashtest_generator_lib",
        "@silifuzz//instruction:xed_util",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest_main",
        "@libxed//:xed",
    ],
)
