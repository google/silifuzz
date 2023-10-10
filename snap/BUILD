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

# Description:
#   Silifuzz Snap library.
#

load(
    "@silifuzz//util:nolibc.bzl",
    "cc_library_plus_nolibc",
)

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

# =========================================================================== #

cc_library_plus_nolibc(
    name = "exit_sequence",
    srcs = [
        "aarch64/exit_sequence.cc",
        "exit_sequence.cc",
        "x86_64/exit_sequence.cc",
    ],
    hdrs = ["exit_sequence.h"],
    deps = [
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util:mem_util",
        "@silifuzz//util/ucontext:ucontext_types",
    ],
)

cc_library_plus_nolibc(
    name = "snap",
    hdrs = ["snap.h"],
    deps = [
        "@silifuzz//util:checks",
        "@silifuzz//util:reg_checksum",
        "@silifuzz//util/ucontext:ucontext_types",
    ],
)

cc_test(
    name = "snap_test",
    size = "small",
    srcs = ["snap_test.cc"],
    deps = [
        ":snap",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library_plus_nolibc(
    name = "snap_relocator",
    srcs = ["snap_relocator.cc"],
    hdrs = ["snap_relocator.h"],
    deps = [
        ":snap",
        ":snap_checksum",
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
        "@silifuzz//util:mmapped_memory_ptr",
    ],
)

cc_test(
    name = "snap_relocator_test",
    srcs = ["snap_relocator_test.cc"],
    deps = [
        ":snap",
        ":snap_relocator",
        "@silifuzz//common:snapshot",
        "@silifuzz//snap/gen:relocatable_snap_generator",
        "@silifuzz//snap/gen:snap_generator",
        "@silifuzz//snap/testing:snap_test_snapshots",
        "@silifuzz//snap/testing:snap_test_types",
        "@silifuzz//util:mmapped_memory_ptr",
        "@silifuzz//util/testing:status_macros",
        "@com_google_absl//absl/status:statusor",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "snap_relocator_fuzz_test",
    srcs = ["snap_relocator_fuzz_test.cc"],
    deps = [
        ":snap_relocator",
        "@silifuzz//util:arch",
        "@silifuzz//util:mmapped_memory_ptr",
        "@com_google_fuzztest//fuzztest",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "snap_util",
    srcs = ["snap_util.cc"],
    hdrs = ["snap_util.h"],
    deps = [
        ":snap",
        "@silifuzz//common:memory_mapping",
        "@silifuzz//common:memory_perms",
        "@silifuzz//common:snapshot",
        "@silifuzz//common:snapshot_util",
        "@silifuzz//util:checks",
        "@silifuzz//util:platform",
        "@com_google_absl//absl/status:statusor",
    ],
)

cc_library_plus_nolibc(
    name = "snap_checksum",
    srcs = [
        "snap_checksum.cc",
    ],
    hdrs = [
        "snap_checksum.h",
    ],
    as_is_deps = [
        "@com_google_absl//absl/strings:string_view",
    ],
    deps = [
        ":snap",
        "@silifuzz//util:crc32c",
    ],
)

cc_test(
    name = "snap_checksum_test",
    size = "medium",
    srcs = ["snap_checksum_test.cc"],
    deps = [
        ":snap",
        ":snap_checksum",
        "@com_google_absl//absl/strings:string_view",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library_plus_nolibc(
    name = "snap_corpus_util",
    srcs = [
        "snap_corpus_util.cc",
    ],
    hdrs = [
        "snap_corpus_util.h",
    ],
    deps = [
        ":snap",
        ":snap_relocator",
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
        "@silifuzz//util:misc_util",
        "@silifuzz//util:mmapped_memory_ptr",
    ],
)

cc_test(
    name = "snap_corpus_util_test",
    size = "medium",
    srcs = ["snap_corpus_util_test.cc"],
    deps = [
        ":snap_corpus_util",
        "@silifuzz//common:snapshot",
        "@silifuzz//snap/gen:relocatable_snap_generator",
        "@silifuzz//snap/gen:snap_generator",
        "@silifuzz//snap/testing:snap_test_snapshots",
        "@silifuzz//snap/testing:snap_test_types",
        "@silifuzz//util:file_util",
        "@silifuzz//util:mmapped_memory_ptr",
        "@silifuzz//util:path_util",
        "@silifuzz//util/testing:status_macros",
        "@silifuzz//util/testing:status_matchers",
        "@com_google_absl//absl/status:statusor",
        "@com_google_googletest//:gtest_main",
    ],
)
