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

"""Provides nolibc build rules.

... these work like cc_library, cc_binary and cc_test rules but are used for
defining targets that use Silifuzz's own libraries instead of the standard libc and
C++ runtime libs. The cc_*_nolibc rules define a target for the nolibc environment.
The actual target name is suffxied with "_nolibc". The cc_*_plus_nolibc rules
define both kinds targets.

We use this method instead of adding a config_setting() for nolibc so that
we can generate a _nolibc binary in the same build as normal binaries and
easily integration-test the two kinds.
"""

load("@rules_cc//cc:cc_binary.bzl", "cc_binary")
load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_cc//cc:cc_test.bzl", "cc_test")

# Disable vector instructions on x86 inside runner
X86_NO_VECTOR_INSN_COPTS = ["-mno-mmx", "-mno-sse", "-mno-avx"]

NOLIBC_COPTS = [
    "-fno-exceptions",  # just to make sure (google3-default)
    "-fno-rtti",  # reduced size/deps
    "-fno-builtin",
] + select({
    # TODO(b/332400982): Restore the setting or clean up depending on the result
    # of the experiment in qpool.
    # "@silifuzz//build_defs/platform:x86_64": X86_NO_VECTOR_INSN_COPTS,
    "//conditions:default": [],
})

NOLIBC_FEATURES = [
    "-use_header_modules",  # incompatible with -fno-rtti
]

NOLIBC_LINKOPTS = [
    "-nostdlib",
    "-nolibc",
]

NOLIBC_STDLIB = [
    "@silifuzz//util:nolibc_main_nolibc",
    "@silifuzz//util:builtins",
]

NOLIBC_LOCAL_DEFINES = ["SILIFUZZ_BUILD_FOR_NOLIBC"]

NOLIBC_DEFAULT_MALLOC = "@bazel_tools//tools/cpp:malloc"

# Adds _nolibc to a dependency. Works for deps like "//path/to/dir" too.
def _add_nolibc_dep_suffix(dep):
    if dep.find(":") == -1:
        return dep + ":" + dep[dep.rindex("/") + 1:] + "_nolibc"
    else:
        return dep + "_nolibc"

def _cc_library_plus_nolibc_impl(
        name,
        hdrs = [],
        srcs = [],
        deps = [],
        as_is_deps = [],
        libc_deps = [],
        nolibc_deps = [],
        copts = [],
        linkstatic = False,
        tags = None,
        nolibc_only = False,
        **rule_kwargs):
    """Generates two variants of cc_library: the normal and the _nolibc one.

    ...by giving the _nolibc one a SILIFUZZ_BUILD_FOR_NOLIBC define and
    using _nolibc variants for all its deps.

    Args:
      name: same as in cc_library
      hdrs: same as in cc_library
      srcs: same as in cc_library
      deps: same as in cc_library
      as_is_deps: deps to which _nolibc suffixing is not applied
      libc_deps: deps for the with-libc case
      nolibc_deps: deps for the no-libc case
      copts: same as in cc_library
      linkstatic: same as in cc_library
      tags: same as in cc_library
      nolibc_only: only create _nolibc variant.
      **rule_kwargs: other args passed to cc_library
    """

    tags = tags or []
    if not nolibc_only:
        cc_library(
            name = name,
            hdrs = hdrs,
            srcs = srcs,
            deps = deps + libc_deps + as_is_deps,
            linkstatic = linkstatic,
            copts = copts,
            tags = tags,
            **rule_kwargs
        )

    deps_nolibc = [_add_nolibc_dep_suffix(d) for d in deps]
    cc_library(
        name = name + "_nolibc",
        hdrs = hdrs,
        srcs = srcs,
        deps = deps_nolibc + nolibc_deps + as_is_deps,
        local_defines = NOLIBC_LOCAL_DEFINES,
        copts = copts + NOLIBC_COPTS,
        linkstatic = linkstatic,
        features = NOLIBC_FEATURES,
        tags = tags + ["avoid_dep"],
        **rule_kwargs
    )

# Like cc_library but the target uses Silifuzz's libraries instead of normal C++ runtime.
def cc_library_nolibc(*args, **kwargs):
    _cc_library_plus_nolibc_impl(nolibc_only = True, *args, **kwargs)

# Like cc_library but define also a nolibc target.
def cc_library_plus_nolibc(*args, **kwargs):
    _cc_library_plus_nolibc_impl(nolibc_only = False, *args, **kwargs)

def _cc_binary_plus_nolibc_impl(
        name,
        srcs = [],
        deps = [],
        as_is_deps = [],
        libc_deps = [],
        nolibc_deps = [],
        copts = [],
        linkopts = [],
        linkstatic = True,
        features = [],
        nolibc_only = False,
        **rule_kwargs):
    """Generates two variants of cc_binary: the normal and the _nolibc one.

    ...by giving the _nolibc one a SILIFUZZ_BUILD_FOR_NOLIBC define,
    using _nolibc variants for all its deps, giving it adjusted args,
    and linking in @silifuzz//util:nolibc_main_nolibc.

    Args:
      name: same as in cc_binary
      srcs: same as in cc_binary
      deps: same as in cc_binary
      as_is_deps: deps to which _nolibc suffixing is not applied
      libc_deps: deps for the with-libc case only
      nolibc_deps: deps for the no-libc case only
      copts: same as in cc_binary
      linkopts: same as in cc_binary
      linkstatic: linkstatic for the with-libc case only
      features: features for the with-libc case only
      nolibc_only: only create _nolibc variant.
      **rule_kwargs: other args passed to cc_binary
    """

    if not nolibc_only:
        cc_binary(
            name = name,
            srcs = srcs,
            deps = deps + libc_deps + as_is_deps,
            copts = copts,
            linkopts = linkopts,
            linkstatic = linkstatic,
            features = features,
            **rule_kwargs
        )

    deps_nolibc = [_add_nolibc_dep_suffix(d) for d in deps]
    cc_binary(
        name = name + "_nolibc",
        srcs = srcs,
        deps = deps_nolibc + nolibc_deps + as_is_deps + NOLIBC_STDLIB,
        local_defines = NOLIBC_LOCAL_DEFINES,
        # The special no-libc args (same as in cc_test_plus_nolibc):
        copts = copts + NOLIBC_COPTS,
        malloc = NOLIBC_DEFAULT_MALLOC,
        linkstatic = 1,
        features = ["fully_static_link"] + NOLIBC_FEATURES,
        linkopts = linkopts + NOLIBC_LINKOPTS,
        **rule_kwargs
    )

# Like cc_binary but the target uses Silifuzz's libraries instead of normal C++ runtime.
def cc_binary_nolibc(*args, **kwargs):
    _cc_binary_plus_nolibc_impl(nolibc_only = True, *args, **kwargs)

def _cc_test_libc_andor_nolibc_impl(
        name,
        srcs = [],
        deps = [],
        as_is_deps = [],
        libc_deps = [],
        nolibc_deps = [],
        copts = [],
        linkopts = [],
        tags = [],
        linkstatic = False,
        features = [],
        nolibc_only = False,
        **rule_kwargs):
    """Generates two variants of test: the normal and the _nolibc one.

    ...by giving the _nolibc one a SILIFUZZ_BUILD_FOR_NOLIBC define,
    using _nolibc variants for all its deps, and giving it adjusted args,
    and linking in @silifuzz//util:nolibc_main_nolibc.

    Args:
      name: same as in cc_test
      srcs: same as in cc_test
      deps: same as in cc_test
      as_is_deps: deps to which _nolibc suffixing is not applied
      libc_deps: deps for the with-libc case only
      nolibc_deps: deps for the no-libc case only
      copts: same as in cc_test
      linkopts: same as in cc_binary
      tags: same as in cc_test
      linkstatic: linkstatic for the with-libc case only
      features: features for the with-libc case only
      nolibc_only: only create _nolibc variant.
      **rule_kwargs: other args passed to cc_test
    """

    if not nolibc_only:
        cc_test(
            name = name,
            srcs = srcs,
            deps = deps + libc_deps + as_is_deps,
            copts = copts,
            linkopts = linkopts,
            tags = tags,
            linkstatic = linkstatic,
            features = features,
            **rule_kwargs
        )

    deps_nolibc = [_add_nolibc_dep_suffix(d) for d in deps]
    cc_test(
        name = name + "_nolibc",
        srcs = srcs,
        deps = deps_nolibc + nolibc_deps + as_is_deps + NOLIBC_STDLIB,
        local_defines = NOLIBC_LOCAL_DEFINES,
        # The special no-libc args (same as in cc_binary_plus_nolibc):
        copts = copts + NOLIBC_COPTS,
        malloc = NOLIBC_DEFAULT_MALLOC,
        linkstatic = 1,
        features = ["fully_static_link"] + NOLIBC_FEATURES,
        linkopts = linkopts + NOLIBC_LINKOPTS,
        # nolibc variant is incompatible with libs needed for sanitizers
        # (it will not link without errors):
        tags = tags + ["nosan", "nozapfhahn"],
        **rule_kwargs
    )

# Like cc_test but built without libc. The resultant test binary is _nolibc suffix.
def cc_test_nolibc(*args, **kwargs):
    _cc_test_libc_andor_nolibc_impl(nolibc_only = True, *args, **kwargs)

# This function pretty much mirrors cc_binary_plus_nolibc but for cc_test.
def cc_test_plus_nolibc(*args, **kwargs):
    _cc_test_libc_andor_nolibc_impl(nolibc_only = False, *args, **kwargs)
