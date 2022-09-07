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

#include "./util/tool_util.h"

#include <vector>

#include "./util/checks.h"

namespace silifuzz {

const char* ConsumeArg(std::vector<char*>& args) {
  DCHECK_GE(args.size(), 1);
  auto arg = args[0];
  args.erase(args.begin());
  return arg;
}

bool ExtraArgs(const std::vector<char*>& args) {
  if (!args.empty()) {
    LOG_ERROR("Unexpected command argument(s).");
    return true;
  }
  return false;
}

}  // namespace silifuzz
