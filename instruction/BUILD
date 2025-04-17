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

# Description:
#  Libraries for undestanding and manipulating machine instructions.
#  Disassemblers, etc, belong here.
#  This code is higher-level than silifuzz/util, but lower-level than silifuzz/common.

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

# =========================================================================== #

DISABLE_ARM_TAGS = [
    "not_build:arm",
    "not_run:arm",
]

cc_library(
    name = "static_insn_filter",
    srcs = ["static_insn_filter.cc"],
    hdrs = ["static_insn_filter.h"],
    deps = [
        "@silifuzz//util:arch",
        "@silifuzz//util:bit_matcher",
        "@abseil-cpp//absl/strings",
    ],
)

cc_test(
    name = "static_insn_filter_test",
    size = "small",
    srcs = ["static_insn_filter_test.cc"],
    deps = [
        ":static_insn_filter",
        "@silifuzz//util:arch",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "xed_util",
    srcs = ["xed_util.cc"],
    hdrs = ["xed_util.h"],
    deps = [
        "@silifuzz//util:platform",
        "@abseil-cpp//absl/base",
        "@libxed//:xed",
    ],
)

cc_test(
    name = "xed_util_test",
    srcs = ["xed_util_test.cc"],
    deps = [
        ":xed_util",
        "@silifuzz//util:arch",
        "@silifuzz//util:itoa",
        "@silifuzz//util:platform",
        "@googletest//:gtest_main",
        "@libxed//:xed",
    ],
)

cc_library(
    name = "decoded_insn",
    srcs = ["decoded_insn.cc"],
    hdrs = ["decoded_insn.h"],
    deps = [
        ":xed_util",
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
        "@silifuzz//util:misc_util",
        "@abseil-cpp//absl/base",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@libxed//:xed",
    ],
)

cc_test(
    name = "decoded_insn_test",
    srcs = ["decoded_insn_test.cc"],
    deps = [
        ":decoded_insn",
        "@silifuzz//util/testing:status_matchers",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@googletest//:gtest_main",
        "@libxed//:xed",
    ],
)

cc_test(
    name = "decoded_insn_fuzz_test",
    srcs = ["decoded_insn_fuzz_test.cc"],
    deps = [
        ":decoded_insn",
        "@silifuzz//util/testing:status_matchers",
        "@fuzztest//fuzztest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "disassembler",
    hdrs = ["disassembler.h"],
)

cc_library(
    name = "capstone_disassembler",
    srcs = ["capstone_disassembler.cc"],
    hdrs = ["capstone_disassembler.h"],
    deps = [
        ":disassembler",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@abseil-cpp//absl/strings",
        "@capstone",
    ],
)

cc_library(
    name = "xed_disassembler",
    srcs = ["xed_disassembler.cc"],
    hdrs = ["xed_disassembler.h"],
    deps = [
        ":disassembler",
        ":xed_util",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@abseil-cpp//absl/strings",
        "@libxed//:xed",
    ],
)

cc_library(
    name = "default_disassembler",
    hdrs = ["default_disassembler.h"],
    deps = [
        ":capstone_disassembler",
        ":xed_disassembler",
        "@silifuzz//util:arch",
    ],
)

cc_test(
    name = "disassembler_test",
    srcs = ["disassembler_test.cc"],
    deps = [
        ":capstone_disassembler",
        ":disassembler",
        ":xed_disassembler",
        "@silifuzz//util:arch",
        "@googletest//:gtest_main",
    ],
)
