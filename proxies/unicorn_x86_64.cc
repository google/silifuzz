// Copyright 2022 The SiliFuzz Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <cstddef>
#include <cstdint>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "./common/proxy_config.h"
#include "./proxies/unicorn_tracer.h"
#include "./util/arch.h"
#include "./util/checks.h"

namespace silifuzz {

absl::Status RunInstructions(absl::string_view instructions,
                             const FuzzingConfig<X86_64> &fuzzing_config,
                             size_t max_inst_executed) {
  UnicornTracer<X86_64> tracer;
  RETURN_IF_NOT_OK(tracer.InitSnippet(instructions, fuzzing_config));

  // Stop at an arbitrary instruction count to avoid infinite loops.
  return tracer.Run(max_inst_executed);
}

}  // namespace silifuzz

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const size_t max_inst_executed = 100;
  absl::Status status = silifuzz::RunInstructions(
      absl::string_view(reinterpret_cast<const char *>(data), size),
      silifuzz::DEFAULT_FUZZING_CONFIG<silifuzz::X86_64>, max_inst_executed);
  if (!status.ok()) {
    LOG_ERROR(status.message());
    return -1;
  }
  return 0;
}
