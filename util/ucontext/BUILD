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
#   Low-level libraries for saving and restoring current CPU state to/from
#   UContext and associated helpers.
#   A better (and no-libc) replacement for getcontext() and setcontext().
#
#   CAVEAT: All the platform-specific code in this directory is for
#   x86_64 Linux. Adjustments would need to be made for higher portability.

load("@silifuzz//util:nolibc.bzl", "cc_library_plus_nolibc")

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

# =========================================================================== #

# TODO(ncbray) enable once ported
DISABLE_ARM_TAGS = [
    "not_build:arm",
    "not_test:arm",
]

cc_library_plus_nolibc(
    name = "ucontext_types",
    hdrs = ["ucontext_types.h"],
    as_is_deps = [
        "@com_google_absl//absl/base:core_headers",
    ],
    deps = [
        "@silifuzz//util:checks",
        "@silifuzz//util:misc_util",
    ],
)

cc_library_plus_nolibc(
    name = "ucontext",
    srcs = [
        "ucontext.cc",
        "aarch64/ucontext.cc",
        "x86_64/ucontext.cc",
    ] + select({
        "@silifuzz//build_defs/platform:aarch64": [
            "aarch64/restore_ucontext_body.inc",
            "aarch64/restore_ucontext_no_syscalls.S",
            "aarch64/restore_ucontext.S",
            "aarch64/save_ucontext_body.inc",
            "aarch64/save_ucontext_no_syscalls.S",
            "aarch64/save_ucontext.S",
        ],
        "@silifuzz//build_defs/platform:x86_64": [
            "//third_party/silifuzz_libunwind:restore_ucontext_body.inc",
            "//third_party/silifuzz_libunwind:restore_ucontext_no_syscalls.S",
            "//third_party/silifuzz_libunwind:restore_ucontext.S",
            "//third_party/silifuzz_libunwind:save_ucontext_body.inc",
            "//third_party/silifuzz_libunwind:save_ucontext_no_syscalls.S",
            "//third_party/silifuzz_libunwind:save_ucontext.S",
            "x86_64/ucontext_offsets.h",
        ],
    }),
    hdrs = ["ucontext.h"],
    as_is_deps = [
        "@com_google_absl//absl/base:core_headers",
    ],
    deps = [
        ":ucontext_types",
        # TODO(b/240319898): non-x86 targets should not depend on this.
        # Either fix cc_library_plus_nolibc or abstract this into a CPU
        # independent target.
        "@silifuzz//util:avx",
    ],
)

genrule(
    name = "ucontext_test_lib_generated_cc",
    srcs = ["x86_64/ucontext_test_lib.cc"],
    outs = ["ucontext_test_lib_generated.cc"],
    cmd = """
        for REG in r8 r9 r10 r11 r12 r13 r14 r15 rdi rsi rbp rbx rdx rax rcx; do
          cat $(SRCS) | sed "s/REG_NAME/$$REG/g" >> "$@"
        done
    """,
)

cc_library(
    name = "ucontext_test_lib",
    testonly = 1,
    srcs = [
        "ucontext_test_lib_generated.cc",
        "x86_64/x86_segment_base.h",
    ],
    hdrs = select({
        "@silifuzz//build_defs/platform:aarch64": [],
        "@silifuzz//build_defs/platform:x86_64": ["x86_64/ucontext_test_lib.h"],
    }),
    copts = [
        # TODO(dougkwan): [impl] Change test to avoid optimization dependency.
        # This code is sensitive to code optimization. If it is built without
        # -O0, TestOneRegister_REG_NAME() in ucontext_test_lib.cc fails.
        "-O0",
    ],
    deps = [
        ":ucontext",
        ":ucontext_types",
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
        "@silifuzz//util:logging_util",
        "@silifuzz//util:misc_util",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_googletest//:gtest",
        "@lss",
    ],
)

# This is a duplicate of :ucontext_test_lib above except for the
# copt -DUCONTEXT_NO_SYSCALLS=1.
cc_library(
    name = "ucontext_no_syscalls_test_lib",
    testonly = 1,
    srcs = ["ucontext_test_lib_generated.cc"],
    hdrs = select({
        "@silifuzz//build_defs/platform:aarch64": [],
        "@silifuzz//build_defs/platform:x86_64": [
            "x86_64/ucontext_test_lib.h",
            "x86_64/x86_segment_base.h",
        ],
    }),
    copts = [
        # This code is sensitive to code optimization. If it is built without
        # -O0, TestOneRegister_REG_NAME() in ucontext_test_lib.cc fails.
        "-O0",
        # Define UCONTEXT_NO_SYSCALLS to build no-syscall variant.
        "-DUCONTEXT_NO_SYSCALLS=1",
    ],
    deps = [
        ":ucontext",
        ":ucontext_types",
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
        "@silifuzz//util:logging_util",
        "@silifuzz//util:misc_util",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_googletest//:gtest",
        "@lss",
    ],
)

cc_test(
    name = "ucontext_test",
    size = "small",
    srcs = select({
        "@silifuzz//build_defs/platform:aarch64": [
            "aarch64/ucontext_test.cc",
            "aarch64/ucontext_test_widgets.S",
        ],
        "@silifuzz//build_defs/platform:x86_64": [
            "x86_64/ucontext_test.cc",
            "x86_64/ucontext_offsets.h",
        ],
    }),
    # The dynamic linker smashes registers and interferes with this test.
    linkstatic = True,
    deps = [
        ":ucontext",
        ":ucontext_types",
        "@com_google_googletest//:gtest_main",
        "@silifuzz//util:checks",
    ] + select({
        "@silifuzz//build_defs/platform:aarch64": [],
        "@silifuzz//build_defs/platform:x86_64": [
            ":ucontext_test_lib",
            "@silifuzz//util:logging_util",
        ],
    }),
)

# This is a duplicate of :ucontext_test above except for the
# copt "-DUCONTEXT_NO_SYSCALLS=1" and the tag "nosan".
cc_test(
    name = "ucontext_no_syscalls_test",
    size = "small",
    srcs = select({
        "@silifuzz//build_defs/platform:aarch64": [
            "aarch64/ucontext_test.cc",
            "aarch64/ucontext_test_widgets.S",
        ],
        "@silifuzz//build_defs/platform:x86_64": [
            "x86_64/ucontext_test.cc",
            "x86_64/ucontext_offsets.h",
        ],
    }),
    copts = [
        "-DUCONTEXT_NO_SYSCALLS=1",
    ],
    # The dynamic linker smashes registers and interferes with this test.
    linkstatic = True,
    deps = [
        ":ucontext",
        ":ucontext_types",
        "@com_google_googletest//:gtest_main",
        "@silifuzz//util:checks",
    ] + select({
        "@silifuzz//build_defs/platform:aarch64": [],
        "@silifuzz//build_defs/platform:x86_64": [
            ":ucontext_no_syscalls_test_lib",
            "@silifuzz//util:logging_util",
        ],
    }),
)

cc_library_plus_nolibc(
    name = "aarch64_esr",
    hdrs = ["aarch64/esr.h"],
    deps = [
        "@silifuzz//util:checks",
    ],
)

cc_library_plus_nolibc(
    name = "x86_traps",
    hdrs = ["x86_64/traps.h"],
)

cc_library_plus_nolibc(
    name = "signal",
    srcs = select({
        "@silifuzz//build_defs/platform:aarch64": [
            "aarch64/signal.cc",
        ],
        "@silifuzz//build_defs/platform:x86_64": [
            "x86_64/signal.cc",
            "x86_64/x86_segment_base.h",
        ],
    }),
    hdrs = ["signal.h"],
    as_is_deps = [
        "@lss",
        "@com_google_absl//absl/base:core_headers",
    ],
    deps = [
        ":ucontext",
        ":ucontext_types",
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
    ],
)

cc_test(
    name = "signal_test",
    size = "small",
    srcs = [
        "signal_test.cc",
        "signal_test.h",
    ] + select({
        "@silifuzz//build_defs/platform:aarch64": [
            "aarch64/signal_test.cc",
            "aarch64/signal_test_widgets.S",
        ],
        "@silifuzz//build_defs/platform:x86_64": [
            "x86_64/signal_test.cc",
            "x86_64/signal_test_widgets.S",
        ],
    }),
    deps = [
        ":signal",
        ":ucontext",
        "@com_google_googletest//:gtest_main",
        "@com_google_absl//absl/base:core_headers",
    ] + select({
        "@silifuzz//build_defs/platform:aarch64": [":aarch64_esr"],
        "@silifuzz//build_defs/platform:x86_64": [":x86_traps"],
    }),
)

cc_library_plus_nolibc(
    name = "serialize",
    srcs = [
        "aarch64/serialize.cc",
        "simple_serialize.h",
        "x86_64/serialize.cc",
    ],
    hdrs = ["serialize.h"],
    as_is_deps = [
        "@com_google_absl//absl/base:core_headers",
    ],
    deps = [
        ":ucontext",
        ":ucontext_types",
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
    ],
)

cc_test(
    name = "serialize_test",
    size = "small",
    srcs = ["serialize_test.cc"],
    deps = [
        ":serialize",
        ":ucontext",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_binary(
    name = "ucontext_offsets_gen",
    srcs = ["x86_64/ucontext_offsets_gen.cc"],
    deps = [":ucontext_types"],
)
