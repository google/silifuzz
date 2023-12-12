// Copyright 2023 The Silifuzz Authors.
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
#include <vector>

#include "external/com_google_fuzztest/centipede/centipede_callbacks.h"
#include "external/com_google_fuzztest/centipede/centipede_default_callbacks.h"
#include "external/com_google_fuzztest/centipede/centipede_interface.h"
#include "external/com_google_fuzztest/centipede/config_file.h"
#include "external/com_google_fuzztest/centipede/defs.h"
#include "external/com_google_fuzztest/centipede/environment.h"
#include "external/com_google_fuzztest/centipede/environment_flags.h"
#include "external/com_google_fuzztest/centipede/mutation_input.h"
#include "external/com_google_fuzztest/centipede/util.h"
#include "./fuzzer/program_mutator.h"

namespace silifuzz {

using centipede::MutationInputRef;

class SilifuzzCentipedeCallbacks : public centipede::CentipedeDefaultCallbacks {
 public:
  SilifuzzCentipedeCallbacks(const centipede::Environment &env)
      : CentipedeDefaultCallbacks(env),
        program_mutator_(centipede::GetRandomSeed(env.seed), env.max_len) {}

  void Mutate(const std::vector<centipede::MutationInputRef> &inputs,
              size_t num_mutants, std::vector<centipede::ByteArray> &mutants) {
    mutants.resize(num_mutants);
    if (num_mutants == 0) return;

    // Re-wrap the input vector so the mutator doesn't need to depend on
    // Centipede's types.
    std::vector<const std::vector<uint8_t> *> tmp;
    tmp.reserve(inputs.size());
    for (const MutationInputRef &input : inputs) {
      tmp.push_back(&input.data);
    }

    // Mutate
    program_mutator_.Mutate(tmp, num_mutants, mutants);

    // TODO(ncbray): fall back to default implementation based on config
  }

 private:
  ProgramMutator program_mutator_;
};

}  // namespace silifuzz

int main(int argc, char **argv) {
  const auto leftover_argv = centipede::config::InitCentipede(argc, argv);
  centipede::Environment env =
      centipede::CreateEnvironmentFromFlags(leftover_argv);
  centipede::DefaultCallbacksFactory<silifuzz::SilifuzzCentipedeCallbacks>
      callbacks;
  return CentipedeMain(env, callbacks);
}
