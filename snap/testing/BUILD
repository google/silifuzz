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
#   Testing helpers and snaphots for the Snap library.
#

load(
    "@silifuzz//util:nolibc.bzl",
    "cc_library_plus_nolibc",
)

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

# =========================================================================== #

cc_library_plus_nolibc(
    name = "snap_test_types",
    testonly = 1,
    hdrs = ["snap_test_types.h"],
    as_is_deps = [
        "@com_google_absl//absl/base:core_headers",
    ],
    deps = [
        "@silifuzz//util:itoa",
    ],
)

cc_library(
    name = "snap_test_snapshots",
    testonly = 1,
    srcs = ["snap_test_snapshots.cc"],
    hdrs = ["snap_test_snapshots.h"],
    deps = [
        ":snap_test_types",
        "@silifuzz//common:memory_perms",
        "@silifuzz//common:snapshot",
        "@silifuzz//common:snapshot_test_enum",
        "@silifuzz//common:snapshot_test_util",
        "@silifuzz//common:snapshot_util",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
        "@silifuzz//util:platform",
        "@silifuzz//util/ucontext:ucontext_types",
    ],
)

cc_binary(
    name = "snap_test_snaps_gen",
    testonly = 1,
    srcs = ["snap_test_snaps_gen.cc"],
    deps = [
        ":snap_test_snapshots",
        "@silifuzz//common:snapshot",
        "@silifuzz//common:snapshot_test_enum",
        "@silifuzz//common:snapshot_test_util",
        "@silifuzz//snap/gen:relocatable_snap_generator",
        "@silifuzz//snap/gen:snap_generator",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util:file_util",
        "@silifuzz//util:misc_util",
        "@silifuzz//util:mmapped_memory_ptr",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

RELOCATABLE_COMMAND = "$(location :snap_test_snaps_gen) --arch={arch} > $@"

genrule(
    name = "relocatable_snap_test_snaps",
    testonly = 1,
    outs = ["test_corpus"],
    cmd = select({
        "@silifuzz//build_defs/platform:aarch64": RELOCATABLE_COMMAND.format(arch = "aarch64"),
        "@silifuzz//build_defs/platform:x86_64": RELOCATABLE_COMMAND.format(arch = "x86_64"),
    }),
    tools = [":snap_test_snaps_gen"],
)

SINGLE_RELOCATABLE_COMMAND = "$(location :snap_test_snaps_gen) --arch={arch} --snapshot_id={snapshot_id} > $@"

genrule(
    name = "relocatable_ends_as_expected",
    testonly = 1,
    outs = ["ends_as_expected_corpus"],
    cmd = select({
        "@silifuzz//build_defs/platform:aarch64": SINGLE_RELOCATABLE_COMMAND.format(
            arch = "aarch64",
            snapshot_id = "kEndsAsExpected",
        ),
        "@silifuzz//build_defs/platform:x86_64": SINGLE_RELOCATABLE_COMMAND.format(
            arch = "x86_64",
            snapshot_id = "kEndsAsExpected",
        ),
    }),
    tools = [":snap_test_snaps_gen"],
)

genrule(
    name = "relocatable_runaway",
    testonly = 1,
    outs = ["runaway_corpus"],
    cmd = select({
        "@silifuzz//build_defs/platform:aarch64": SINGLE_RELOCATABLE_COMMAND.format(
            arch = "aarch64",
            snapshot_id = "kRunaway",
        ),
        "@silifuzz//build_defs/platform:x86_64": SINGLE_RELOCATABLE_COMMAND.format(
            arch = "x86_64",
            snapshot_id = "kRunaway",
        ),
    }),
    tools = [":snap_test_snaps_gen"],
)

cc_library(
    name = "snap_generator_test_lib",
    testonly = 1,
    srcs = ["snap_generator_test_lib.cc"],
    hdrs = ["snap_generator_test_lib.h"],
    deps = [
        "@silifuzz//common:mapped_memory_map",
        "@silifuzz//common:memory_perms",
        "@silifuzz//common:snapshot",
        "@silifuzz//common:snapshot_util",
        "@silifuzz//snap",
        "@silifuzz//snap/gen:snap_generator",
        "@silifuzz//util:checks",
        "@silifuzz//util:mem_util",
        "@silifuzz//util:reg_checksum",
        "@silifuzz//util:reg_checksum_util",
        "@silifuzz//util/ucontext:serialize",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)
