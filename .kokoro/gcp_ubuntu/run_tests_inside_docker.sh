#!/bin/bash
# Copyright 2018 Google LLC
# Copyright 2022 SiliFuzz Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set -eu

./install_build_dependencies.sh
apt install -y rename

########################################
# LOG ENVIRONMENT DEBUG INFO
########################################
date --rfc-3339=seconds
echo Debug Info

mkdir -p "${KOKORO_ARTIFACTS_DIR}"
find . > "${KOKORO_ARTIFACTS_DIR}/full_file_list.log"
echo KOKORO_ARTIFACTS_DIR="${KOKORO_ARTIFACTS_DIR}"
printenv >> "${KOKORO_ARTIFACTS_DIR}/build_environment.log"
which bazel >> "${KOKORO_ARTIFACTS_DIR}/build_environment.log"
bazel version >> "${KOKORO_ARTIFACTS_DIR}/build_environment.log"
bazel info --show_make_env >> "${KOKORO_ARTIFACTS_DIR}/build_environment.log"

########################################
# RUN TESTS
########################################
date --rfc-3339=seconds
echo Preparing Bazel

BAZEL_OUTPUT_DIR=$(bazel info output_base)

BAZEL_ARGS="--color=no --curses=no --noshow_progress"

date --rfc-3339=seconds

set +e
bazel build ${BAZEL_ARGS}  runner/... orchestrator/... tools/...
bazel test ${BAZEL_ARGS}  runner/... orchestrator/... tools/...

exit_code=$?
set -e

# Capture the build log as a fake test to reduce download spam
FULL_BUILD_LOG_FILE=bazel_full_build_log
mkdir -p "${KOKORO_ARTIFACTS_DIR}/${FULL_BUILD_LOG_FILE}"
cp "${BAZEL_OUTPUT_DIR}/command.log" "${KOKORO_ARTIFACTS_DIR}/${FULL_BUILD_LOG_FILE}/sponge_log.log"
(cat << DOC
<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="">
  <testsuite name="${FULL_BUILD_LOG_FILE}" tests="1" errors="${exit_code}"></testsuite>
</testsuites>
DOC
) > "${KOKORO_ARTIFACTS_DIR}/${FULL_BUILD_LOG_FILE}/sponge_log.xml"

########################################
# REMAP OUTPUT FILES
########################################
KOKORO_BAZEL_LOGS_DIR="${KOKORO_ARTIFACTS_DIR}/bazel_test_logs"
mkdir -p "${KOKORO_BAZEL_LOGS_DIR}"

# copy test.log files to kokoro artifacts directory, then rename then.
find -L bazel-testlogs -name "test.log" -exec cp --parents {} "${KOKORO_BAZEL_LOGS_DIR}" \;
find -L "${KOKORO_BAZEL_LOGS_DIR}" -name "test.log" -exec rename 's/test\.log/sponge_log.log/' {} \;
find -L bazel-testlogs -name "test.xml" -exec cp --parents {} "${KOKORO_BAZEL_LOGS_DIR}" \;
find -L "${KOKORO_BAZEL_LOGS_DIR}" -name "test.xml" -exec rename 's/test\.xml/sponge_log.xml/' {} \;

date --rfc-3339=seconds
echo Exiting Docker

exit ${exit_code}
