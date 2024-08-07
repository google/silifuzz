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
        "instruction_pool.cc",
        "prefilter.cc",
        "register_info.cc",
        "synthesize_base.cc",
        "synthesize_instruction.cc",
        "synthesize_shuffle.cc",
        "synthesize_test.cc",
        "xed_operand_util.cc",
    ],
    hdrs = [
        "candidate.h",
        "debugging.h",
        "instruction_pool.h",
        "prefilter.h",
        "rand_util.h",
        "register_info.h",
        "synthesize_base.h",
        "synthesize_instruction.h",
        "synthesize_shuffle.h",
        "synthesize_test.h",
        "weighted_choose_one.h",
        "xed_operand_util.h",
    ],
    deps = [
        "@silifuzz//instruction:xed_util",
        "@silifuzz//util:checks",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/strings:string_view",
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

cc_binary(
    name = "hashtest_generator",
    srcs = [
        "hashtest_generator_main.cc",
        "synthesize_snapshot.cc",
        "synthesize_snapshot.h",
    ],
    deps = [
        ":hashtest_generator_lib",
        "@silifuzz//common:raw_insns_util",
        "@silifuzz//common:snapshot",
        "@silifuzz//common:snapshot_file_util",
        "@silifuzz//common:snapshot_printer",
        "@silifuzz//instruction:xed_util",
        "@silifuzz//runner:make_snapshot",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util:enum_flag_types",
        "@silifuzz//util:itoa",
        "@silifuzz//util:line_printer",
        "@silifuzz//util:platform",
        "@silifuzz//util/ucontext:ucontext_types",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:string_view",
        "@libxed//:xed",
    ],
)

sh_test(
    name = "hashtest_generator_integration_test",
    srcs = ["hashtest_generator_integration_test.sh"],
    data = [
        ":hashtest_generator",
    ],
)
