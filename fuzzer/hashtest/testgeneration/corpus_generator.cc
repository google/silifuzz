// Copyright 2026 The Silifuzz Authors.
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

#include "./fuzzer/hashtest/testgeneration/corpus_generator.h"

#include <sys/mman.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <random>
#include <utility>
#include <vector>

#include "absl/log/check.h"
#include "absl/types/span.h"
#include "./fuzzer/hashtest/entropy.h"
#include "./fuzzer/hashtest/parallel_worker_pool.h"
#include "./fuzzer/hashtest/runnable_corpus.h"
#include "./fuzzer/hashtest/test_partition.h"
#include "./fuzzer/hashtest/testgeneration/candidate.h"
#include "./fuzzer/hashtest/testgeneration/instruction_pool.h"
#include "./fuzzer/hashtest/testgeneration/synthesis_config.h"
#include "./fuzzer/hashtest/testgeneration/synthesize_base.h"
#include "./fuzzer/hashtest/testgeneration/synthesize_test.h"
#include "./instruction/xed_util.h"
#include "./util/page_util.h"

namespace silifuzz {
namespace {

void SynthesizeTest(uint64_t seed, xed_chip_enum_t chip,
                    const SynthesisConfig& config, InstructionBlock& body) {
  std::mt19937_64 rng(seed);
  RegisterPool rpool{};
  InitRegisterLayout(chip, rpool);

  // Clear rdi since it is dirty from jumping to the test.
  // Setting it to the seed for the test adds entropy and embeds the seed in the
  // test itself.
  InstructionBuilder clear_rdi_builder(XED_ICLASS_MOV, 64U);
  clear_rdi_builder.AddOperands(xed_reg(XED_REG_RDI), xed_imm0(seed, 64));
  Emit(clear_rdi_builder, body);

  SynthesizeLoopBody(rng, rpool, config, body);

  // Decrement the loop counter at the end of the loop body.
  SynthesizeGPRegDec(kLoopIndex, body);

  // Using JNLE so that the loop will abort if an SDC causes us to miss zero
  // or jump to a negative index.
  SynthesizeBackwardJnle(-static_cast<int32_t>(body.bytes.size()), body);

  SynthesizeReturn(body);
  size_t padding = (16 - (body.bytes.size() % 16)) % 16;
  SynthesizeBreakpointTraps(16 + padding, body);
}

size_t SynthesizeTests(absl::Span<Test> tests, uint8_t* code_buffer,
                       uint8_t* buffer_limit, xed_chip_enum_t chip,
                       const SynthesisConfig& config) {
  size_t offset = 0;
  for (Test& test : tests) {
    InstructionBlock body{};
    SynthesizeTest(test.seed, chip, config, body);

    // Copy the test into the mapping.
    // TODO(b/473040142): move the writing code into InstructionBlock or into an
    // object that understands the limits of the buffer in a better way than
    // passing around a buffer_limit pointer.
    test.code = code_buffer + offset;
    size_t test_size = body.bytes.size();
    CHECK_LE(test_size, kMaxTestBytes);
    CHECK_LE(reinterpret_cast<uint8_t*>(test.code) + test_size, buffer_limit);
    memcpy(test.code, body.bytes.data(), test_size);
    offset += test_size;
  }
  return offset;
}

}  // namespace

RunnableCorpus CorpusGenerator::GenerateCorpusForConfig(
    const GenerationConfig& config,
    std::function<bool(const InstructionCandidate&)> instruction_filter,
    ParallelWorkerPool& workers) {
  // Use the seed for generating the instruction pool.
  rng_.seed(config.seed);
  if (ipool_.empty() || chip_for_ipool_ != config.chip) {
    GenerateInstructionPool(rng_, config.chip, ipool_, false);
    chip_for_ipool_ = config.chip;
  }

  // Re-use the seed to generate inputs and tests (in the case where we want to
  // change the order in which operations are performed later, re-using the seed
  // allows us to do this without affecting the generated corpus.)
  rng_.seed(config.seed);
  std::vector<Input> inputs = GenerateInputs(config.num_inputs);

  // Allocate corpus backed memory in line rather than in a function.  Because
  // the MemoryMapping class deletes its move constructor, we can only get the
  // guaranteed copy-elision if we use aggregate initialization at the end of
  // the function.
  size_t mapping_size =
      RoundUpToPageAlignment(kMaxTestBytes * config.num_tests);
  void* mapping_ptr = mmap(0, mapping_size, PROT_READ | PROT_WRITE,
                           MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  // TODO(danieljsnyder): handle error gracefully.
  CHECK_NE(mapping_ptr, MAP_FAILED);

  rng_.seed(config.seed);
  std::vector<Test> tests(config.num_tests);
  for (size_t i = 0; i < config.num_tests; ++i) {
    // Initialize the test seeds now to prevent partitioning or parallelization
    // from affecting the outcome of test generation.
    tests[i].seed = GetSeed(rng_);
  }

  // Generate the tests in parallel.
  // TODO(danieljsnyder): generate tests redundantly to catch SDCs?
  struct SynthesizeTestsTask {
    absl::Span<Test> tests;
    // The start of the buffer for this subtask.
    uint8_t* code_buffer;
    // The limit address for this subtask.
    uint8_t* buffer_limit;
    size_t used;
  };

  std::vector<SynthesizeTestsTask> tasks(workers.NumWorkers());
  for (size_t i = 0; i < tasks.size(); ++i) {
    TestPartition partition =
        GetPartition(i, config.num_tests, workers.NumWorkers());
    // Each task is given a chunk of the code mapping large enough to hold the
    // maximum code size for all the tests in the partition. In practice
    // almost all of the tests will be smaller than the maximum size and the
    // code will be packed end to end for each task to improve locality. There
    // will be gaps in the code mapping between the packed code generated by
    // each task. The size of the code buffer for each task is implicitly:
    // partition.size * kMaxTestBytes.
    uint8_t* code_buffer = reinterpret_cast<uint8_t*>(mapping_ptr) +
                           partition.offset * kMaxTestBytes;

    size_t tests_in_partition = partition.size;
    uint8_t* max_addr_for_partition =
        std::min(reinterpret_cast<uint8_t*>(mapping_ptr) + mapping_size,
                 code_buffer + tests_in_partition * kMaxTestBytes);
    tasks[i] = {
        .tests =
            absl::MakeSpan(tests).subspan(partition.offset, partition.size),
        .code_buffer = code_buffer,
        .buffer_limit = max_addr_for_partition,
        .used = 0,
    };
  }
  InstructionPool filtered_ipool = ipool_.Filter(instruction_filter);
  SynthesisConfig synthesis_config = {
      .ipool = &filtered_ipool,
      .flag_capture_rate = config.flag_capture_rate,
      .mask_trap_flag = config.mask_trap_flag,
      .min_duplication_rate = config.min_duplication_rate,
      .max_duplication_rate = config.max_duplication_rate,
      .branch_test_bits = config.branch_test_bits,
  };

  workers.DoWork(tasks, [&](SynthesizeTestsTask& task) {
    task.used = SynthesizeTests(task.tests, task.code_buffer, task.buffer_limit,
                                config.chip, synthesis_config);
  });

  // Calculate the amount of memory used.
  // TODO(b/473040142): The size is currently an incorrect value.  It assumes
  // the test partitions have no space between them which is unlikely to be the
  // case.
  size_t used = 0;
  for (const SynthesizeTestsTask& task : tasks) {
    used += task.used;
  }

  // Finish generating the test content by marking it as executable.
  CHECK_EQ(0, mprotect(mapping_ptr, mapping_size, PROT_READ | PROT_EXEC));

  return RunnableCorpus{
      .mapping = MemoryMapping(mapping_ptr, mapping_size, used),
      .tests = std::move(tests),
      .inputs = std::move(inputs)};
}

std::vector<Input> CorpusGenerator::GenerateInputs(size_t num_inputs) {
  std::vector<Input> inputs;
  inputs.resize(num_inputs);
  for (size_t i = 0; i < num_inputs; i++) {
    uint64_t seed = GetSeed(rng_);
    inputs[i].seed = seed;
    RandomizeEntropyBuffer(seed, inputs[i].entropy);
  }
  return inputs;
}

}  // namespace silifuzz
