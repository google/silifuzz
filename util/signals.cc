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

#include <csignal>
#include <cstring>

#include "./util/checks.h"

namespace silifuzz {

void IgnoreSignal(int sig) {
  struct sigaction sig_action = {};
  sig_action.sa_handler = SIG_IGN;
  sigemptyset(&sig_action.sa_mask);
  if (sigaction(sig, &sig_action, nullptr) < 0) {
    LOG_FATAL("Couldn't ignore ", strsignal(sig));
  }
}

}  // namespace silifuzz
