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

#include "absl/flags/flag.h"
#include "absl/log/log.h"
#include "external/com_google_fuzztest/centipede/centipede_callbacks.h"
#include "external/com_google_fuzztest/centipede/centipede_default_callbacks.h"
#include "external/com_google_fuzztest/centipede/centipede_interface.h"
#include "external/com_google_fuzztest/centipede/config_file.h"
#include "external/com_google_fuzztest/centipede/environment.h"
#include "external/com_google_fuzztest/centipede/environment_flags.h"
#include "external/com_google_fuzztest/centipede/mutation_input.h"
#include "external/com_google_fuzztest/centipede/util.h"
#include "external/com_google_fuzztest/common/defs.h"
#include "./fuzzer/program_batch_mutator.h"
#include "./util/arch.h"
#include "./util/enum_flag_types.h"
#include "./util/itoa.h"

ABSL_FLAG(silifuzz::ArchitectureId, arch, silifuzz::ArchitectureId::kUndefined,
          "Architecture for instruction-aware fuzzing.");

namespace silifuzz {

using fuzztest::internal::MutationInputRef;

class SilifuzzCentipedeCallbacks
    : public fuzztest::internal::CentipedeDefaultCallbacks {
 public:
  SilifuzzCentipedeCallbacks(const fuzztest::internal::Environment &env)
      : CentipedeDefaultCallbacks(env),
        arch_(absl::GetFlag(FLAGS_arch)),
        x86_64_mutator_(fuzztest::internal::GetRandomSeed(env.seed),
                        env.crossover_level / 100.0, env.max_len),
        aarch64_mutator_(fuzztest::internal::GetRandomSeed(env.seed),
                         env.crossover_level / 100.0, env.max_len) {}

  std::vector<fuzztest::internal::ByteArray> Mutate(
      const std::vector<fuzztest::internal::MutationInputRef> &inputs,
      size_t num_mutants) override {
    // Fall back to the byte mutator if the architecture was not specified.
    if (arch_ == ArchitectureId::kUndefined) {
      return fuzztest::internal::CentipedeDefaultCallbacks::Mutate(inputs,
                                                                   num_mutants);
    }

    // Init
    std::vector<fuzztest::internal::ByteArray> mutants{num_mutants};
    if (num_mutants == 0) return mutants;

    // Re-wrap the input vector so the mutator doesn't need to depend on
    // Centipede's types.
    std::vector<const std::vector<uint8_t> *> tmp;
    tmp.reserve(inputs.size());
    for (const MutationInputRef &input : inputs) {
      tmp.push_back(&input.data);
    }

    // Mutate
    switch (arch_) {
      case ArchitectureId::kX86_64:
        x86_64_mutator_.Mutate(tmp, num_mutants, mutants);
        break;
      case ArchitectureId::kAArch64:
        aarch64_mutator_.Mutate(tmp, num_mutants, mutants);
        break;
      default:
        LOG(FATAL) << "Unknown architecture: " << (int)arch_;
    }

    return mutants;
  }

 private:
  ArchitectureId arch_;
  ProgramBatchMutator<X86_64> x86_64_mutator_;
  ProgramBatchMutator<AArch64> aarch64_mutator_;
};

}  // namespace silifuzz

int main(int argc, char **argv) {
  const auto runtime_state = fuzztest::internal::InitCentipede(argc, argv);
  fuzztest::internal::Environment env =
      fuzztest::internal::CreateEnvironmentFromFlags(
          runtime_state->leftover_argv());
  LOG(INFO) << "Mutator arch: " << silifuzz::EnumStr(absl::GetFlag(FLAGS_arch));
  fuzztest::internal::DefaultCallbacksFactory<
      silifuzz::SilifuzzCentipedeCallbacks>
      callbacks;
  return CentipedeMain(env, callbacks);
}
