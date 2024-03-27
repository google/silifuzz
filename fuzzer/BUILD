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
        "program_aarch64.cc",
        "program_batch_mutator.cc",
        "program_mutation_ops.cc",
        "program_x86_64.cc",
    ],
    hdrs = [
        "program.h",
        "program_arch.h",
        "program_batch_mutator.h",
        "program_mutation_ops.h",
        "program_mutator.h",
    ],
    deps = [
        "@silifuzz//instruction:capstone_disassembler",
        "@silifuzz//instruction:static_insn_filter",
        "@silifuzz//instruction:xed_util",
        "@silifuzz//util:arch",
        "@silifuzz//util:bit_matcher",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/strings:string_view",
        "@com_google_absl//absl/types:span",
        "@libxed//:xed",
    ],
)

cc_test(
    name = "program_mutator_test",
    size = "medium",
    srcs = ["program_mutator_test.cc"],
    deps = [
        ":program_mutator",
        "@silifuzz//util:arch",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "program_mutator_fuzz_test",
    srcs = ["program_mutator_fuzz_test.cc"],
    deps = [
        ":program_mutator",
        "@silifuzz//util:arch",
        "@com_google_fuzztest//fuzztest",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_binary(
    name = "silifuzz_centipede",
    srcs = [
        "silifuzz_centipede_main.cc",
    ],
    deps = [
        ":program_mutator",
        "@silifuzz//util:arch",
        "@silifuzz//util:enum_flag_types",
        "@silifuzz//util:itoa",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:flags",
        "@com_google_fuzztest//centipede:centipede_callbacks",
        "@com_google_fuzztest//centipede:centipede_default_callbacks",
        "@com_google_fuzztest//centipede:centipede_interface",
        "@com_google_fuzztest//centipede:config_file",
        "@com_google_fuzztest//centipede:defs",
        "@com_google_fuzztest//centipede:environment",
        "@com_google_fuzztest//centipede:environment_flags",
        "@com_google_fuzztest//centipede:mutation_input",
        "@com_google_fuzztest//centipede:util",
    ],
)
