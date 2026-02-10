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
#   All SiliFuzz ptotocol messages are to live here.
#   Exceptions are example or for-test protos with very local usage scope.

load("@protobuf//bazel:cc_proto_library.bzl", "cc_proto_library")
load("@rules_proto//proto:defs.bzl", "proto_library")
load("@rules_python//python:proto.bzl", "py_proto_library")

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

# =========================================================================== #

proto_library(
    name = "snapshot",
    srcs = ["snapshot.proto"],
)

cc_proto_library(
    name = "snapshot_cc_proto",
    deps = [":snapshot"],
)

py_proto_library(
    name = "snapshot_py_proto",
    deps = [":snapshot"],
)

proto_library(
    name = "player_result",
    srcs = ["player_result.proto"],
    deps = [
        ":snapshot",
        "@protobuf//:duration_proto",
    ],
)

cc_proto_library(
    name = "player_result_cc_proto",
    deps = [":player_result"],
)

py_proto_library(
    name = "player_result_py_proto",
    deps = [":player_result"],
)

proto_library(
    name = "corpus_metadata_proto",
    srcs = ["corpus_metadata.proto"],
)

cc_proto_library(
    name = "corpus_metadata_cc_proto",
    deps = [":corpus_metadata_proto"],
)

proto_library(
    name = "session_summary_proto",
    srcs = ["session_summary.proto"],
    deps = [
        "corpus_metadata_proto",
        "@protobuf//:duration_proto",
    ],
)

cc_proto_library(
    name = "session_summary_cc_proto",
    deps = [":session_summary_proto"],
)

proto_library(
    name = "snapshot_execution_result_proto",
    srcs = ["snapshot_execution_result.proto"],
    deps = [
        ":player_result",
        "@protobuf//:timestamp_proto",
    ],
)

cc_proto_library(
    name = "snapshot_execution_result_cc_proto",
    deps = [":snapshot_execution_result_proto"],
)

py_proto_library(
    name = "snapshot_execution_result_py_proto",
    deps = [":snapshot_execution_result_proto"],
)

proto_library(
    name = "binary_log_entry_proto",
    srcs = ["binary_log_entry.proto"],
    deps = [
        ":session_summary_proto",
        ":snapshot_execution_result_proto",
        "@protobuf//:any_proto",
        "@protobuf//:timestamp_proto",
    ],
)

cc_proto_library(
    name = "binary_log_entry_cc_proto",
    deps = [":binary_log_entry_proto"],
)

py_proto_library(
    name = "binary_log_entry_py_pb2",
    deps = [":binary_log_entry_proto"],
)
