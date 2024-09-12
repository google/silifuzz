// Copyright 2024 The Silifuzz Authors.
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

#include "./fuzzer/hashtest/hashtest_runner.h"

#include <sys/mman.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include "absl/log/check.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "third_party/cityhash/city.h"
#include "./fuzzer/hashtest/hashtest_runner_widgits.h"
#include "./fuzzer/hashtest/instruction_pool.h"
#include "./fuzzer/hashtest/synthesize_base.h"
#include "./fuzzer/hashtest/synthesize_test.h"
#include "./instruction/xed_util.h"
#include "./util/cpu_id.h"
#include "./util/page_util.h"

namespace silifuzz {

std::string FormatSeed(uint64_t seed) {
  return absl::StrCat(absl::Hex(seed, absl::kZeroPad16));
}

void RandomizeEntropyBuffer(uint64_t seed, EntropyBuffer& buffer) {
  std::independent_bits_engine<Rng, sizeof(uint8_t) * 8, uint8_t> engine(seed);
  std::generate(std::begin(buffer.bytes), std::end(buffer.bytes), engine);
}

MemoryMapping::~MemoryMapping() {
  if (ptr_ != nullptr) {
    CHECK_EQ(munmap(ptr_, allocated_size_), 0);
  }
}

void DumpTest(uint64_t start_address, InstructionBlock& body) {
  xed_decoded_inst_t xed_insn;
  char formatted_insn_buf[96];

  size_t offset = 0;

  while (offset < body.bytes.size()) {
    xed_decoded_inst_zero(&xed_insn);
    xed_decoded_inst_set_mode(&xed_insn, XED_MACHINE_MODE_LONG_64,
                              XED_ADDRESS_WIDTH_64b);

    xed_error_enum_t xed_error = xed_decode(
        &xed_insn, body.bytes.data() + offset, body.bytes.size() - offset);
    CHECK(xed_error == XED_ERROR_NONE);
    CHECK(xed_decoded_inst_valid(&xed_insn));
    CHECK(FormatInstruction(xed_insn, start_address + offset,
                            formatted_insn_buf, sizeof(formatted_insn_buf)));
    std::cout << std::hex << std::setfill('0') << std::setw(16)
              << start_address + offset << ": " << formatted_insn_buf << "\n";
    offset += xed_decoded_inst_get_length(&xed_insn);
  }
  std::cout << std::dec;
}

void SynthesizeTest(uint64_t seed, xed_chip_enum_t chip,
                    const InstructionPool& ipool, InstructionBlock& body) {
  Rng rng(seed);
  RegisterPool rpool{};
  InitRegisterLayout(chip, rpool);

  SynthesizeLoopBody(rng, ipool, rpool, body);

  // Decrement the loop counter at the end of the loop body.
  SynthesizeGPRegDec(kLoopIndex, body);

  // Using JNLE so that the loop will abort if an SDC causes us to miss zero
  // or jump to a negative index.
  SynthesizeJnle(-(int32_t)body.bytes.size(), body);

  SynthesizeReturn(body);
  size_t padding = (16 - (body.bytes.size() % 16)) % 16;
  SynthesizeBreakpointTraps(16 + padding, body);
}

Corpus AllocateCorpus(Rng& rng, size_t num_tests) {
  size_t mapping_size = RoundUpToPageAlignment(kMaxTestBytes * num_tests);
  void* ptr = mmap(0, mapping_size, PROT_READ | PROT_WRITE,
                   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  // TODO(ncbray): handle error gracefully.
  CHECK_NE(ptr, MAP_FAILED);

  std::vector<Test> tests(num_tests);
  for (size_t i = 0; i < num_tests; ++i) {
    // Initialize the test seeds now to prevent partitioning or parallelization
    // from affecting the outcome of test generation.
    tests[i].seed = GetSeed(rng);
  }

  return Corpus{
      .tests = std::move(tests),
      .mapping = MemoryMapping(ptr, mapping_size, 0),
  };
}

size_t SynthesizeTests(absl::Span<Test> tests, uint8_t* code_buffer,
                       xed_chip_enum_t chip, const InstructionPool& ipool) {
  size_t offset = 0;
  for (Test& test : tests) {
    InstructionBlock body{};
    SynthesizeTest(test.seed, chip, ipool, body);

    // Copy the test into the mapping.
    test.code = code_buffer + offset;
    size_t test_size = body.bytes.size();
    CHECK_LE(test_size, kMaxTestBytes);
    memcpy(test.code, body.bytes.data(), test_size);
    offset += test_size;
  }
  return offset;
}

void FinalizeCorpus(Corpus& corpus, size_t used_size) {
  // Make test memory read-only and executable.
  // TODO(ncbray): handle error gracefully.
  CHECK_EQ(0, mprotect(corpus.mapping.Ptr(), corpus.mapping.AllocatedSize(),
                       PROT_READ | PROT_EXEC));
  corpus.mapping.SetUsedSize(used_size);
}

void ResultReporter::CheckIn() {
  absl::MutexLock lock(&mutex);
  absl::Time now = absl::Now();
  if (now >= next_update) {
    std::cout << hits.size() << " hits" << "\n";
    next_update = now + update_period;
  }
  if (now >= testing_deadline) {
    SetShouldHalt();
  }
}

void ResultReporter::ReportHit(int cpu, size_t test_index, const Test& test,
                               size_t input_index, const Input& input) {
  absl::MutexLock lock(&mutex);

  hits.push_back({
      .cpu = cpu,
      .test_index = test_index,
      .test_seed = test.seed,
      .input_index = input_index,
      .input_seed = input.seed,
  });
}

void RunHashTest(void* test, const TestConfig& config,
                 const EntropyBuffer& input, EntropyBuffer& output) {
  if (config.vector_width == 512) {
    RunHashTest512(test, config.num_iterations, &input, &output);
  } else if (config.vector_width == 256) {
    RunHashTest256(test, config.num_iterations, &input, &output);
  } else {
    CHECK(false) << "Unsupported vector width: " << config.vector_width;
  }
#if defined(MEMORY_SANITIZER)
  __msan_unpoison(output.bytes, output.NumBytes(config.vector_width));
#endif
}

uint64_t EntropyBufferHash(const EntropyBuffer& buffer, size_t vector_width) {
  return CityHash64(reinterpret_cast<const char*>(&buffer.bytes),
                    buffer.NumBytes(vector_width));
}

void ComputeEndStates(absl::Span<const Test> tests, const TestConfig& config,
                      absl::Span<const Input> inputs,
                      absl::Span<EndState> end_states) {
  CHECK_EQ(tests.size() * inputs.size(), end_states.size());
  for (size_t t = 0; t < tests.size(); ++t) {
    for (size_t i = 0; i < inputs.size(); i++) {
      EntropyBuffer output;
      RunHashTest(tests[t].code, config, inputs[i].entropy, output);
      end_states[t * inputs.size() + i].hash =
          EntropyBufferHash(output, config.vector_width);
    }
  }
}

// Given three end states, select the one that occurs at least twice and return
// true. If all the end states are different, return false.
bool ReconcileEndState(EndState& end_state, const EndState& other1,
                       const EndState& other2) {
  if (end_state.hash == other1.hash) {
    return true;
  }
  if (end_state.hash == other2.hash) {
    return true;
  }
  if (other1.hash == other2.hash) {
    end_state.hash = other1.hash;
    return true;
  }

  // No two of the end states match.
  end_state.SetCouldNotBeComputed();
  return false;
}

size_t ReconcileEndStates(absl::Span<EndState> end_state,
                          absl::Span<const EndState> other1,
                          absl::Span<const EndState> other2) {
  CHECK_EQ(end_state.size(), other1.size());
  CHECK_EQ(end_state.size(), other2.size());
  size_t fail_count = 0;
  for (size_t i = 0; i < end_state.size(); ++i) {
    if (!ReconcileEndState(end_state[i], other1[i], other2[i])) {
      fail_count++;
    }
  }
  return fail_count;
}

void RunTest(size_t test_index, const Test& test, const TestConfig& config,
             size_t input_index, const Input& input, const EndState& expected,
             ThreadStats& stats, ResultReporter& result) {
  // Run the test.
  EntropyBuffer actual;
  RunHashTest(test.code, config, input.entropy, actual);
  ++stats.num_run;

  // Compare the end state.
  bool ok = expected.hash == EntropyBufferHash(actual, config.vector_width);

  if (!ok) {
    ++stats.num_failed;
    result.ReportHit(GetCPUId(), test_index, test, input_index, input);
  }
}

bool RunBatch(absl::Span<const Test> tests, absl::Span<const Input> inputs,
              absl::Span<const EndState> end_states, const RunConfig& config,
              size_t test_offset, ThreadStats& stats, ResultReporter& result) {
  // Repeat the batch.
  for (size_t r = 0; r < config.num_repeat; ++r) {
    // Sweep through each input.
    for (size_t i = 0; i < inputs.size(); i++) {
      const Input& input = inputs[i];
      // Sweep through each test in the batch.
      // The point of having a batch size > 1 is that the same test will not be
      // run multiple times in a row.
      for (size_t t = 0; t < tests.size(); ++t) {
        const Test& test = tests[t];
        const EndState& expected = end_states[t * inputs.size() + i];
        if (expected.CouldNotBeComputed()) {
          continue;
        }
        size_t test_index = test_offset + t;
        RunTest(test_index, test, config.test, i, input, expected, stats,
                result);
        // This should occur ~2.5 times a second.
        // We want to check in often enough so that we have a timely heat beat,
        // but not so often that it creates lock contention.
        if (stats.num_run % 100000 == 0) {
          result.CheckIn();
        }
        if (result.ShouldHalt()) {
          return false;
        }
      }
    }
  }
  return true;
}

void RunTests(absl::Span<const Test> tests, absl::Span<const Input> inputs,
              absl::Span<const EndState> end_states, const RunConfig& config,
              size_t test_offset, ThreadStats& stats, ResultReporter& result) {
  for (size_t g = 0; g < tests.size(); g += config.batch_size) {
    size_t batch_size = std::min(config.batch_size, tests.size() - g);
    bool keep_running = RunBatch(
        tests.subspan(g, batch_size), inputs,
        end_states.subspan(g * inputs.size(), batch_size * inputs.size()),
        config, test_offset + g, stats, result);
    if (!keep_running) {
      return;
    }
  }
}

}  // namespace silifuzz
