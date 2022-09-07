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

"""Transition configuration to build sanitizer-free binaries."""

# This transition removes various sanitizer-related compiler flags and build
# options. Allows us to have nolibc binaries as data-dependencies of potentially
# sanitized tests.
# See https://docs.bazel.build/versions/3.2.0/skylark/config.html#user-defined-transitions
def _nosan_transition_impl(settings, attr):
    features_to_strip = ["asan", "tsan", "msan"]
    filtered_features = [x for x in settings["//command_line_option:features"] if x not in features_to_strip]
    return {
        "//command_line_option:custom_malloc": None,  # minimize deps
        "//command_line_option:compiler": None,
        "//command_line_option:features": filtered_features,
        "//command_line_option:strip": "always",
        "//command_line_option:stripopt": ["--strip-all"],
        "//command_line_option:copt": settings["//command_line_option:copt"] + ["-fno-sanitize=all"],
        "//command_line_option:linkopt": settings["//command_line_option:linkopt"] + ["-fno-sanitize=all"],
    }

# A transition that defines inputs and output to
# _nosan_transition_impl above.
_nosan_transition = transition(
    implementation = _nosan_transition_impl,
    inputs = [
        "//command_line_option:features",
        "//command_line_option:copt",
        "//command_line_option:linkopt",
    ],
    outputs = [
        "//command_line_option:custom_malloc",
        "//command_line_option:compiler",
        "//command_line_option:features",
        "//command_line_option:strip",
        "//command_line_option:stripopt",
        "//command_line_option:copt",
        "//command_line_option:linkopt",
    ],
)

def _nosan_filegroup_config_impl(ctx):
    runfiles = ctx.runfiles(files = ctx.files.srcs)

    # Expand all the runfiles of data deps.
    for data in ctx.attr.data:
        runfiles = runfiles.merge(data.default_runfiles)

    return [DefaultInfo(
        files = runfiles.files,
        runfiles = runfiles,
    )]

_nosan_filegroup = rule(
    implementation = _nosan_filegroup_config_impl,
    attrs = {
        "srcs": attr.label_list(
            cfg = _nosan_transition,
            allow_files = True,
        ),
        "data": attr.label_list(
            cfg = _nosan_transition,
        ),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
)

def nosan_filegroup(name, **kwargs):
    """Like a `filegroup`, but forces all its sources to be compiled without any sanitizer instrumentation.

    Args:
      name: A unique name for this target
      **kwargs: all other args
    """

    _nosan_filegroup(name = name, **kwargs)
