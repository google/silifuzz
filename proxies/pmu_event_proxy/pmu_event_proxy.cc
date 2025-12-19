// Copyright 2023 The SiliFuzz Authors.
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

// PMU Event Proxy
//
// This is a centipede fuzz target that executes arbitrary CPU instruction blobs
// and record PMU event count changes during execution. The event counts are
// converted into coverage features for consumption by centipede.
//
#include <sys/prctl.h>
#include <sys/resource.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "centipede/feature.h"
#include "./common/memory_perms.h"
#include "./common/proxy_config.h"
#include "./common/snapshot_enums.h"
#include "./instruction/default_disassembler.h"
#include "./proxies/arch_feature_generator.h"
#include "./proxies/pmu_event_proxy/perf_event_fuzzer.h"
#include "./proxies/pmu_event_proxy/pmu_events.h"
#include "./proxies/user_features.h"
#include "./proxies/util/set_process_dumpable.h"
#include "./tracing/extension_registers.h"
#include "./tracing/native_tracer.h"
#include "./tracing/tracer.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "perfmon/pfmlib.h"
#include "perfmon/pfmlib_perf_event.h"

ABSL_FLAG(size_t, num_iterations, 10,
          "Number of iterations to run each input.");

// This array lives in an ELF segment that the Centipede runner will read from.
USER_FEATURE_ARRAY user_feature_t features[100000];

namespace silifuzz {

namespace {

// These are global so that LLVMFuzzerTestOneInput() can see them.
std::vector<std::string> *pmu_events;
PerfEventFuzzer *perf_event_fuzzer;
DefaultDisassembler<Host>* disasm;
ArchFeatureGenerator<Host>* feature_gen;

constexpr ArchFeatureDomains kArchFeatureDomains = {3, 4, 5, 6, 7, 8, 9, 0};

// Convert a non-zero PMU event 'count' of the 'i-th' event to a user
// feature by its MSB position. This maps 'count' into one of the 8 feature
// bits.
uint32_t Convert8BitCountToUserFeature(size_t i, uint8_t count) {
  CHECK_NE(count, 0);
  // Compute a log2 of counter_value, i.e. a value between 0 and 7.
  // __builtin_clz consumes an unsigned int.
  const unsigned int unsigned_count = static_cast<unsigned int>(count);
  const uint32_t counter_log2 =
      sizeof(unsigned_count) * 8 - 1 - __builtin_clz(unsigned_count);
  return i * 8 + counter_log2;
}

template <typename Arch, size_t CHUNK_SIZE>
void EmitMemoryFeaturesForSegment(TracerControl<Arch>& control,
                                  snapshot_types::Address& start,
                                  snapshot_types::Address limit,
                                  snapshot_types::Address segment_base,
                                  size_t feature_base,
                                  uint8_t (&mem)[CHUNK_SIZE]) {
  while (start >= segment_base && start + CHUNK_SIZE <= limit) {
    size_t offset = start - segment_base;
    control.ReadMemory(start, mem, CHUNK_SIZE);
    feature_gen->FinalMemoryWithIndex(feature_base + offset, mem);
    start += CHUNK_SIZE;
  }
}

// Emit features for memory bits that are different from the initial state.
// The initial state is zero, so we can skip the diff.
// (The initial stack state is not entirely zero, but close enough.)
template <typename Arch>
void EmitMemoryFeatures(TracerControl<Arch>& control,
                        const FuzzingConfig<Host>& fuzzing_config) {
  constexpr size_t kMemBytesPerChunk = 4096;
  // With 1 << 27 feature space, we can generate bitwise memory features for
  // 4096 pages. But that would be too many coverage points and make corpus size
  // explode. Set limit to 32 data pages and 1 stack page.
  constexpr size_t kMaxDataPages = 32;
  // In each data segment, limit the feature generation for the first
  // (kMaxDataPages / 2) pages.
  const size_t kFeatureLimitPerSegment = kMemBytesPerChunk * kMaxDataPages / 2;
#ifdef __x86_64__
  const size_t stack_base = fuzzing_config.data1_range.start_address;
  const size_t data_base1 = stack_base + kMemBytesPerChunk;
  const size_t data_base2 = fuzzing_config.data2_range.start_address;
#elif defined __aarch64__
  const size_t stack_base = fuzzing_config.stack_range.start_address;
  const size_t data_base1 = fuzzing_config.data1_range.start_address;
  const size_t data_base2 = fuzzing_config.data2_range.start_address;
#endif

  uint8_t mem[kMemBytesPerChunk];
  control.IterateMappedMemory([&](snapshot_types::Address start,
                                  snapshot_types::Address limit,
                                  MemoryPerms perms) {
    if (!perms.Has(MemoryPerms::kWritable)) return;
    // Compress the memory address into the feature space of (kMaxDataPages + 1)
    // pages:
    // - stack: [0, kMemBytesPerChunk)
    // - data1: [kMemBytesPerChunk, kMemBytesPerChunk + kFeatureLimitPerSegment)
    // - data2: [kMemBytesPerChunk + kFeatureLimitPerSegment, kMemBytesPerChunk,
    // kMemBytesPerChunk + kFeatureLimitPerSegment * 2]
    if (start == stack_base) {
      control.ReadMemory(start, mem, kMemBytesPerChunk);
      feature_gen->FinalMemoryWithIndex(0, mem);
      start += kMemBytesPerChunk;
    }
    EmitMemoryFeaturesForSegment(
        control, start,
        /*limit=*/std::min(data_base1 + kFeatureLimitPerSegment, limit),
        /*segment_base=*/data_base1,
        /*feature_base=*/kMemBytesPerChunk, mem);
    EmitMemoryFeaturesForSegment(
        control, start,
        /*limit=*/std::min(data_base2 + kFeatureLimitPerSegment, limit),
        /*segment_base=*/data_base2,
        /*feature_base=*/kMemBytesPerChunk + kFeatureLimitPerSegment, mem);
  });
}

template <typename Arch>
constexpr inline uint64_t MaxInstructionLength();

template <>
constexpr inline uint64_t MaxInstructionLength<X86_64>() {
  return 15;
}

template <>
[[maybe_unused]] constexpr inline uint64_t MaxInstructionLength<AArch64>() {
  return 4;
}

template <typename Arch>
bool DisassembleCurrentInstruction(TracerControl<Arch>& tracer) {
  uint8_t buf[MaxInstructionLength<Arch>()];
  const uint64_t addr = tracer.GetInstructionPointer();
  const uint64_t max_size = MaxInstructionLength<Arch>();
  tracer.ReadMemory(addr, buf, max_size);
  return disasm->Disassemble(addr, buf, max_size);
}

absl::Status TraceAndGenerateExecutionFeatures(
    absl::string_view instructions, const FuzzingConfig<Host>& fuzzing_config,
    size_t max_inst_executed) {
  NativeTracer tracer;
  RETURN_IF_NOT_OK_PLUS(
      tracer.InitSnippet(instructions, TracerConfig<Host>{}, fuzzing_config),
      "Failed to init snippet");

  feature_gen->BeforeInput(features);
  // The tracer interface defines callbacks before the instruction executes.
  // We need to do a little extra work to synthesize a callback after every
  // instruction.
  uint32_t instruction_id = kInvalidInstructionId;
  bool instruction_pending = false;
  bool instructions_are_in_range = true;
  ExtUContext<Host> registers{};

  auto after_instruction = [&](TracerControl<Host>& control) {
    if (instruction_pending) {
      control.GetRegisters(registers, &registers.eregs);
      feature_gen->AfterInstruction(instruction_id, registers);
      instruction_pending = false;
    }
  };

  tracer.SetBeforeExecutionCallback([&](TracerControl<Host>& control) {
    control.GetRegisters(registers, &registers.eregs);
    feature_gen->BeforeExecution(registers);
  });

  tracer.SetBeforeInstructionCallback(
      [&](TracerControl<Host>& control, uint64_t address) {
        after_instruction(control);

        if (DisassembleCurrentInstruction(control)) {
          instruction_id = disasm->InstructionID();
          CHECK_LT(instruction_id, disasm->NumInstructionIDs());
          instructions_are_in_range &=
              control.InstructionIsInRange(address, disasm->InstructionSize());
        } else {
          instruction_id = kInvalidInstructionId;
        }

        instruction_pending = true;
      });

  tracer.SetAfterExecutionCallback([&](TracerControl<Host>& control) {
    // Flush the last instruction.
    after_instruction(control);
    feature_gen->AfterExecution();
    EmitMemoryFeatures(control, fuzzing_config);
  });

  // Stop at an arbitrary instruction count to avoid infinite loops.
  absl::Status status = tracer.Run(max_inst_executed);
  if (!instructions_are_in_range) {
    return absl::OutOfRangeError(
        "Instructions are not entirely contained in code.");
  }
  return status;
}

// Executes a payload at 'data' of 'size' bytes.  Returns 0 if we should keep
// the payload for fuzzing or -1 if we should discard it.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // First run the payload with the tracer to generate execution features.
  absl::Status trace_status = silifuzz::TraceAndGenerateExecutionFeatures(
      absl::string_view(reinterpret_cast<const char*>(data), size),
      silifuzz::DEFAULT_FUZZING_CONFIG<Host>, 4000);
  if (!trace_status.ok()) {
    return -1;
  }

  // Then run the payload with the perf event fuzzer to generate PMU event
  // features.
  absl::StatusOr<PerfEventFuzzer::PerfEventMeasurementList> event_measurements =
      perf_event_fuzzer->FuzzOneInput(data, size,
                                      absl::GetFlag(FLAGS_num_iterations));
  if (!event_measurements.ok()) {
    LOG(ERROR) << "Failed to test one input: " << event_measurements.status();
    return -1;
  }

  // We generate two kinds of coverage from PMU event counts.
  // 1. Count values: Counter values are clipped to fit in the range
  // [0..255]. Each value in the range is a distinct feature. Due to noise
  // in counter reading, feature generation is non-deterministic.
  // Fuzzing inputs are usually very short with O(100) instructions so we do not
  // expect large event counts. 8 bits seem to be a good estimate. We can scale
  // count values or increase the range if 8 bits are not sufficient.
  // 2. Count value pairs: Non-zero count values are paired to form a
  // single feature. This is quadratic so we compress the count values
  // by taking using the MSB only. The stored feature is thus a pair of
  // MSBs.

  std::vector<uint32_t> compressed_counts;

  constexpr int kPMUCounterDomain = 1;
  constexpr size_t kMaxCount = 255;
  CHECK_EQ(event_measurements->size(), pmu_events->size());
  for (size_t i = 0; i < pmu_events->size(); ++i) {
    PerfEventMeasurements &measurements = event_measurements.value()[i];
    CHECK_EQ(measurements.event(), (*pmu_events)[i]);
    const double count =
        measurements.mean().has_value() ? measurements.mean().value() : 0;
    const double clipped =
        static_cast<uint32_t>(std::min<double>(count, kMaxCount));
    feature_gen->EmitFeature(kPMUCounterDomain, i * (kMaxCount + 1) + clipped);
    if (clipped > 0) {
      // 256 count features are compressed into 8.
      compressed_counts.push_back(Convert8BitCountToUserFeature(i, clipped));
    }
  }

  constexpr int kPMUCounterPairDomain = 2;
  size_t d = pmu_events->size() * 8;
  for (size_t i = 1; i < compressed_counts.size(); ++i) {
    for (size_t j = 0; j < i; ++j) {
      const uint64_t pair = compressed_counts[i] * d + compressed_counts[j];
      DCHECK_LT(pair, fuzztest::internal::feature_domains::Domain::kDomainSize);
      feature_gen->EmitFeature(kPMUCounterPairDomain, pair);
    }
  }

  return 0;
}

absl::Status PMUEventProxyInitialize(int *argc, char ***argv) {
  absl::ParseCommandLine(*argc, *argv);

  pfm_err_t init_err = pfm_initialize();
  if (init_err != PFM_SUCCESS) {
    return absl::InternalError(
        absl::StrCat("Failed to initialize libpfm: ", pfm_strerror(init_err)));
  }

  // Revert dumpable setting for snap maker to work.
  // See comments in set_process_dumpable.h for details.
  RETURN_IF_NOT_OK(proxies::SetProcessDumpable());

  // Get PMU perf events.
  // TODO(dougkwan): Instead of calling GetUniqueFilteredCPUCorePMUEvents(), use
  // a file containing events to fuzz.
  ASSIGN_OR_RETURN_IF_NOT_OK(std::vector<std::string> events,
                             GetUniqueFilteredCPUCorePMUEvents());
  pmu_events = new std::vector<std::string>();
  pmu_events->swap(events);

  perf_event_fuzzer = new PerfEventFuzzer(*pmu_events);
  disasm = new DefaultDisassembler<Host>();
  feature_gen = new ArchFeatureGenerator<Host>(kArchFeatureDomains);
  feature_gen->BeforeBatch(disasm->NumInstructionIDs());

  return absl::OkStatus();
}

}  // namespace

}  // namespace silifuzz

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  absl::Status status = silifuzz::PMUEventProxyInitialize(argc, argv);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to initialize PMU Event proxy: " << status;
    return -1;
  }
  return 0;
}
