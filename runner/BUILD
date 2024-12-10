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
#   SiliFuzz Snapshot runner
#

load(
    "@silifuzz//build_defs:constants.bzl",
    "SILIFUZZ_RUNNER_BASE_ADDRESS",
)
load("@silifuzz//build_defs:nosan.bzl", "nosan_filegroup")
load(
    "@silifuzz//util:nolibc.bzl",
    "cc_binary_nolibc",
    "cc_library_nolibc",
    "cc_library_plus_nolibc",
    "cc_test_nolibc",
)

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

# =========================================================================== #

cc_library_plus_nolibc(
    name = "loading_snap_corpus",
    srcs = ["loading_snap_corpus.cc"],
    hdrs = ["default_snap_corpus.h"],
    deps = [
        "@silifuzz//snap",
        "@silifuzz//snap:snap_corpus_util",
        "@silifuzz//util:arch",
    ],
)

cc_library_plus_nolibc(
    name = "endspot",
    srcs = ["endspot.cc"],
    hdrs = ["endspot.h"],
    deps = [
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
        "@silifuzz//util:logging_util",
        "@silifuzz//util:mem_util",
        "@silifuzz//util:reg_checksum",
        "@silifuzz//util/ucontext",
        "@silifuzz//util/ucontext:signal",
        "@silifuzz//util/ucontext:ucontext_types",
    ],
)

cc_library_plus_nolibc(
    name = "snap_runner_util",
    srcs = ["snap_runner_util.cc"] + select({
        "@silifuzz//build_defs/platform:aarch64": [
            "aarch64/snap_exit.S",
        ],
        "@silifuzz//build_defs/platform:x86_64": [
            "x86_64/snap_exit.S",
        ],
    }),
    hdrs = ["snap_runner_util.h"],
    # This can only be built as a static library as it would
    # crash the dynamic linker due to invalid fs_base on x86.
    linkstatic = 1,
    deps = [
        ":endspot",
        ":runner_main_options",
        "@silifuzz//snap:exit_sequence",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
        "@silifuzz//util:logging_util",
        "@silifuzz//util:mem_util",
        "@silifuzz//util:misc_util",
        "@silifuzz//util:reg_group_io",
        "@silifuzz//util/ucontext",
        "@silifuzz//util/ucontext:signal",
        "@silifuzz//util/ucontext:ucontext_types",
        "@silifuzz//util/ucontext:x86_traps",
    ],
)

cc_test_nolibc(
    name = "snap_runner_util_test",
    timeout = "short",
    srcs = select({
        "@silifuzz//build_defs/platform:aarch64": [
            "aarch64/snap_runner_util_test.cc",
        ],
        "@silifuzz//build_defs/platform:x86_64": [
            "x86_64/snap_runner_util_test.cc",
        ],
    }),
    as_is_deps = [
        "@com_google_absl//absl/base:core_headers",
    ],
    features = ["fully_static_link"],
    linkstatic = 1,
    deps = [
        ":endspot",
        ":runner_main_options",
        ":snap_runner_util",
        "@silifuzz//snap:exit_sequence",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
        "@silifuzz//util:nolibc_gunit",
        "@silifuzz//util:reg_groups",
        "@silifuzz//util:sve",
        "@silifuzz//util/ucontext",
        "@silifuzz//util/ucontext:ucontext_types",
    ],
)

cc_library_plus_nolibc(
    name = "runner_main_options",
    hdrs = ["runner_main_options.h"],
    deps = [
        "@silifuzz//snap",
        "@silifuzz//util:arch",
        "@silifuzz//util:cpu_id",
    ],
)

cc_library_plus_nolibc(
    name = "runner_util",
    srcs = [
        "runner_util.cc",
    ] + select({
        "@silifuzz//build_defs/platform:aarch64": [
            "aarch64/runner_util.cc",
        ],
        "@silifuzz//build_defs/platform:x86_64": [
            "x86_64/runner_util.cc",
        ],
    }),
    hdrs = [
        "runner_util.h",
    ],
    as_is_deps = [
        "@com_google_absl//absl/base:core_headers",
    ],
    # This can only be built as a static library as it would
    # crash the dynamic linker due to invalid fs_base on x86.
    linkstatic = 1,
    deps = [
        ":endspot",
        "@silifuzz//common:snapshot_enums",
        "@silifuzz//snap",
        "@silifuzz//util:arch",
        "@silifuzz//util:byte_io",
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
        "@silifuzz//util:proc_maps_parser",
        "@silifuzz//util/ucontext",
        "@silifuzz//util/ucontext:aarch64_esr",
        "@silifuzz//util/ucontext:signal",
        "@silifuzz//util/ucontext:x86_traps",
    ],
)

cc_library_nolibc(
    name = "runner",
    srcs = [
        "runner.cc",
    ],
    hdrs = [
        "runner.h",
    ],
    as_is_deps = [
        "@lss",
    ],
    # This can only be built as a static library as it would
    # crash the dynamic linker due to invalid fs_base on x86.
    linkstatic = 1,
    deps = [
        ":endspot",
        ":runner_main_options",
        ":runner_util",
        ":snap_runner_util",
        "@silifuzz//common:snapshot_enums",
        "@silifuzz//snap",
        "@silifuzz//snap:exit_sequence",
        "@silifuzz//snap:snap_checksum",
        "@silifuzz//util:arch",
        "@silifuzz//util:atoi",
        "@silifuzz//util:byte_io",
        "@silifuzz//util:checks",
        "@silifuzz//util:cpu_id",
        "@silifuzz//util:itoa",
        "@silifuzz//util:logging_util",
        "@silifuzz//util:mem_util",
        "@silifuzz//util:misc_util",
        "@silifuzz//util:page_util",
        "@silifuzz//util:proc_maps_parser",
        "@silifuzz//util:reg_checksum",
        "@silifuzz//util:reg_group_io",
        "@silifuzz//util:reg_group_set",
        "@silifuzz//util:reg_groups",
        "@silifuzz//util:text_proto_printer",
        "@silifuzz//util/ucontext:serialize",
        "@silifuzz//util/ucontext:signal",
        "@silifuzz//util/ucontext:ucontext_types",
    ],
)

cc_test_nolibc(
    name = "runner_test",
    timeout = "short",
    srcs = ["runner_test.cc"],
    data = [
        "@silifuzz//snap/testing:test_corpus",
    ],
    env = {"TEST_CORPUS": "$(location @silifuzz//snap/testing:test_corpus)"},
    linkopts = [
        "-Xlinker",
        "--image-base=" + SILIFUZZ_RUNNER_BASE_ADDRESS,
    ],
    linkstatic = 1,
    deps = [
        ":loading_snap_corpus",
        ":runner",
        ":runner_main_options",
        ":runner_util",
        ":snap_runner_util",
        "@silifuzz//common:snapshot_test_enum",
        "@silifuzz//snap",
        "@silifuzz//snap:exit_sequence",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
        "@silifuzz//util:nolibc_gunit",
        "@silifuzz//util:reg_group_io",
        "@silifuzz//util:reg_group_set",
        "@silifuzz//util:reg_groups",
    ],
)

cc_library_nolibc(
    name = "runner_flags",
    srcs = ["runner_flags.cc"],
    hdrs = ["runner_flags.h"],
    deps = [
        ":runner",
        "@silifuzz//util:atoi",
        "@silifuzz//util:checks",
        "@silifuzz//util:cpu_id",
        "@silifuzz//util:flag_matcher",
    ],
)

cc_test(
    name = "runner_integration_test",
    size = "medium",
    srcs = ["runner_integration_test.cc"],
    data = [
        "@silifuzz//snap/testing:test_corpus",
    ],
    deps = [
        ":runner_provider",
        "@silifuzz//common:proxy_config",
        "@silifuzz//common:snapshot",
        "@silifuzz//common:snapshot_enums",
        "@silifuzz//common:snapshot_test_enum",
        "@silifuzz//common:snapshot_test_util",
        "@silifuzz//runner/driver:runner_driver",
        "@silifuzz//runner/driver:runner_options",
        "@silifuzz//snap/gen:relocatable_snap_generator",
        "@silifuzz//snap/testing:snap_test_snapshots",
        "@silifuzz//util:arch",
        "@silifuzz//util:data_dependency",
        "@silifuzz//util:file_util",
        "@silifuzz//util:itoa",
        "@silifuzz//util:mmapped_memory_ptr",
        "@silifuzz//util:path_util",
        "@silifuzz//util/testing:status_macros",
        "@silifuzz//util/testing:status_matchers",
        "@silifuzz//util/ucontext:serialize",
        "@silifuzz//util/ucontext:ucontext_types",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "disassembling_snap_tracer",
    srcs = ["disassembling_snap_tracer.cc"] + select({
        "@silifuzz//build_defs/platform:aarch64": [
            "aarch64/disassembling_snap_tracer.cc",
        ],
        "@silifuzz//build_defs/platform:x86_64": [
            "x86_64/disassembling_snap_tracer.cc",
        ],
    }),
    hdrs = ["disassembling_snap_tracer.h"],
    deps = [
        "@silifuzz//common:harness_tracer",
        "@silifuzz//common:snapshot",
        "@silifuzz//instruction:default_disassembler",
        "@silifuzz//player:trace_options",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ] + select({
        "@silifuzz//build_defs/platform:aarch64": [
        ],
        "@silifuzz//build_defs/platform:x86_64": [
            "@silifuzz//instruction:decoded_insn",
        ],
    }),
)

cc_test(
    name = "disassembling_snap_tracer_test",
    size = "medium",
    srcs =
        select({
            "@silifuzz//build_defs/platform:aarch64": [
                "aarch64/disassembling_snap_tracer_test.cc",
            ],
            "@silifuzz//build_defs/platform:x86_64": [
                "x86_64/disassembling_snap_tracer_test.cc",
            ],
        }),
    data = [
        "@silifuzz//snap/testing:test_corpus",
    ],
    deps = [
        ":disassembling_snap_tracer",
        ":runner_provider",
        "@silifuzz//common:snapshot_enums",
        "@silifuzz//common:snapshot_test_enum",
        "@silifuzz//player:trace_options",
        "@silifuzz//runner/driver:runner_driver",
        "@silifuzz//snap/testing:snap_test_snapshots",
        "@silifuzz//util:arch",
        "@silifuzz//util:data_dependency",
        "@silifuzz//util/testing:status_macros",
        "@silifuzz//util/testing:status_matchers",
        "@com_google_absl//absl/functional:bind_front",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "snap_maker",
    srcs = ["snap_maker.cc"],
    hdrs = ["snap_maker.h"],
    deps = [
        "@silifuzz//common:mapped_memory_map",
        "@silifuzz//common:memory_bytes_set",
        "@silifuzz//common:memory_mapping",
        "@silifuzz//common:memory_perms",
        "@silifuzz//common:proxy_config",
        "@silifuzz//common:snapshot",
        "@silifuzz//common:snapshot_enums",
        "@silifuzz//common:snapshot_printer",
        "@silifuzz//player:trace_options",
        "@silifuzz//runner/driver:runner_driver",
        "@silifuzz//snap/gen:reserved_memory_mappings",
        "@silifuzz//snap/gen:snap_generator",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util:cpu_id",
        "@silifuzz//util:itoa",
        "@silifuzz//util:line_printer",
        "@silifuzz//util:page_util",
        "@silifuzz//util:platform",
        "@com_google_absl//absl/functional:bind_front",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ] + select({
        "@silifuzz//build_defs/platform:aarch64": [
        ],
        "@silifuzz//build_defs/platform:x86_64": [
            ":disassembling_snap_tracer",
        ],
    }),
)

cc_library(
    name = "snap_maker_test_util",
    testonly = True,
    srcs = ["snap_maker_test_util.cc"],
    hdrs = ["snap_maker_test_util.h"],
    data = [
        ":sanless_reading_runner_main_nolibc",
    ],
    deps = [
        ":runner_provider",
        ":snap_maker",
        "@silifuzz//common:snapshot",
        "@silifuzz//player:trace_options",
        "@com_google_absl//absl/status:statusor",
    ],
)

cc_test(
    name = "snap_maker_test",
    size = "medium",
    srcs = ["snap_maker_test.cc"],
    deps = [
        ":snap_maker",
        ":snap_maker_test_util",
        "@silifuzz//common:snapshot",
        "@silifuzz//common:snapshot_test_enum",
        "@silifuzz//player:trace_options",
        "@silifuzz//snap/testing:snap_test_snapshots",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util/testing:status_macros",
        "@silifuzz//util/testing:status_matchers",
        "@silifuzz//util/testing:vsyscall",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "make_snapshot",
    srcs = ["make_snapshot.cc"],
    hdrs = ["make_snapshot.h"],
    deps = [
        "@silifuzz//common:proxy_config",
        "@silifuzz//common:raw_insns_util",
        "@silifuzz//common:snapshot",
        "@silifuzz//common:snapshot_enums",
        "@silifuzz//player:trace_options",
        "@silifuzz//runner:snap_maker",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util:cpu_id",
        "@silifuzz//util:itoa",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

# Build main() for the runner as a library so that we
# can link it into different versions of the runner.
cc_library_nolibc(
    name = "runner_main_as_lib",
    srcs = ["runner_main.cc"],
    # Include just the header. Actual implementation
    # is added by one {runner_main,reading_runner_main}
    hdrs = ["default_snap_corpus.h"],
    as_is_deps = [
        "@com_google_absl//absl/base:core_headers",
        "@lss",
    ],
    linkstatic = 1,
    deps = [
        ":runner",
        ":runner_flags",
        ":runner_main_options",
        "@silifuzz//snap",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util:strcat",
    ],
)

cc_binary_nolibc(
    name = "reading_runner_main",
    linkopts = [
        "-Xlinker",
        "--image-base=" + SILIFUZZ_RUNNER_BASE_ADDRESS,
    ],
    deps = [
        ":loading_snap_corpus",
        ":runner_main_as_lib",
    ],
)

sh_test(
    name = "global_static_initializers_test",
    timeout = "short",
    srcs = ["global_static_initializers_test.sh"],
    data = [":reading_runner_main_nolibc"],
)

nosan_filegroup(
    name = "sanless_reading_runner_main_nolibc",
    srcs = [
        ":reading_runner_main_nolibc",
    ],
)

# A single library for obtaining all runner binaries that can be depended on
# in any compilation configuration (i.e. it's *SAN-compatible).
cc_library(
    name = "runner_provider",
    srcs = ["runner_provider.cc"],
    hdrs = ["runner_provider.h"],
    data = [
        ":sanless_reading_runner_main_nolibc",
    ],
    deps = [
        "@silifuzz//util:checks",
        "@silifuzz//util:data_dependency",
    ],
)

cc_test(
    name = "runner_provider_test",
    size = "medium",
    timeout = "short",
    srcs = ["runner_provider_test.cc"],
    deps = [
        ":runner_provider",
        "@com_google_googletest//:gtest_main",
    ],
)
