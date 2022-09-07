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

// Simple benchmark of Memory utility
//
// To run:
//
// bazel run -c opt third_party/silifuzz/util:mem_util_benchmark_nolibc
//
// We have no gunit benchmarking functionality in nolibc environment.
// Hence we need to do this.
//
// Here is result from running it on a 2.0GHz Skylake.
//
// I<DATE> <PID> mem_util_benchmark.cc:190] Benchmarking MemEq
// I<DATE> <PID> mem_util_benchmark.cc:194] 16B : 3069 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 256B : 18686 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 4096B : 20816 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 65536B : 21467 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 1048576B : 21654 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:190] Benchmarking bcmp
// I<DATE> <PID> mem_util_benchmark.cc:194] 16B : 1510 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 256B : 2010 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 4096B : 2158 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 65536B : 2126 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 1048576B : 2112 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:190] Benchmarking MemEqSSE
// I<DATE> <PID> mem_util_benchmark.cc:194] 16B : 3187 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 256B : 18717 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 4096B : 20835 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 65536B : 21518 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 1048576B : 21564 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:190] Benchmarking MemCopy
// I<DATE> <PID> mem_util_benchmark.cc:194] 16B : 4094 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 256B : 22506 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 4096B : 23525 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 65536B : 21394 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 1048576B : 20608 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:190] Benchmarking memcpy
// I<DATE> <PID> mem_util_benchmark.cc:194] 16B : 1230 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 256B : 1460 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 4096B : 1536 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 65536B : 1547 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 1048576B : 1538 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:190] Benchmarking MemSet
// I<DATE> <PID> mem_util_benchmark.cc:194] 16B : 4472 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 256B : 23486 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 4096B : 24514 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 65536B : 21865 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 1048576B : 20718 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:190] Benchmarking memset
// I<DATE> <PID> mem_util_benchmark.cc:194] 16B : 1799 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 256B : 2717 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 4096B : 3046 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 65536B : 2803 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 1048576B : 2810 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:190] Benchmarking MemAllEqualTo
// I<DATE> <PID> mem_util_benchmark.cc:194] 16B : 3766 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 256B : 21301 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 4096B : 25406 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 65536B : 23892 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:194] 1048576B : 21730 MiB/s
//
#include <cstdint>
#include <cstring>
#include <functional>

#include "third_party/lss/lss/linux_syscall_support.h"
#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/mem_util.h"

namespace silifuzz {
namespace {

// This is built for the nolibc environment, there is no memory allocator.
// Use static buffer for testing.

#define BUFFER_SIZE (1 << 20)
alignas(sizeof(uint64_t)) char test_buffer_1[BUFFER_SIZE];
alignas(sizeof(uint64_t)) char test_buffer_2[BUFFER_SIZE];

typedef bool (*MemoryCompareFunc)(const void* s1, const void* s2, size_t n);
typedef void (*MemoryCopyFunc)(void* dest, const void* src, size_t n);
typedef void (*MemorySetFunc)(void* dest, uint8_t c, size_t n);
typedef bool (*MemoryAllEqualToFunc)(const void* src, uint8_t c, size_t n);

bool BcmpAdaptor(const void* s1, const void* s2, size_t n) {
  return bcmp(s1, s2, n) == 0;
}

// A faster version of MemEq using SSE. This is not used for the time being
// as SSE usage is considered not desirable. Not having SSE will make a Snapshot
// player more sensitive to some bugs as the player itself does not perturb SSE
// state.
bool MemEqSSE(const void* s1, const void* s2, size_t n) {
  CHECK_EQ(reinterpret_cast<uintptr_t>(s1) % sizeof(uint64_t), 0);
  CHECK_EQ(reinterpret_cast<uintptr_t>(s2) % sizeof(uint64_t), 0);
  CHECK_EQ(n % sizeof(uint64_t), 0);
  size_t num_u64s = n / sizeof(uint64_t);
  const uint64_t* u1 = reinterpret_cast<const uint64_t*>(s1);
  const uint64_t* u2 = reinterpret_cast<const uint64_t*>(s2);
  uint64_t diff_bits = 0;
  for (size_t i = 0; i < num_u64s; ++i) {
    diff_bits |= u1[i] ^ u2[i];
  }
  return diff_bits == 0;
}

void MemcpyAdaptor(void* dest, const void* src, size_t n) {
  memcpy(dest, src, n);
}

// Wrapper for memset() in nolibc_main.cc
void NolibcMemsetAdaptor(void* s, uint8_t c, size_t n) { memset(s, c, n); }

// Returns number of virtual nano seconds since start of the current thread.
uint64_t GetThreadVirtualTimeNano() {
  kernel_timespec tp{0};
  CHECK_EQ(sys_clock_gettime(MAKE_THREAD_CPUCLOCK(0, CPUCLOCK_SCHED), &tp), 0);
  return tp.tv_sec * static_cast<uint64_t>(1000000000) + tp.tv_nsec;
}

// Rounds up size to given alignment.
inline size_t RoundUp(size_t size, size_t alignment) {
  return (size + alignment - 1) / alignment * alignment;
}

// Returns bandwidth in bytes processed per second for a memory function.
// function.
inline uint64_t MeasureBandwidth(
    std::function<void(size_t, size_t)> do_one_iteration, size_t size) {
  CHECK_LE(size, BUFFER_SIZE);

  size_t aligned_size = RoundUp(size, sizeof(uint64_t));

  // Estimate roughly number of iterations in 1ms
  size_t num_iterations_in_1ms = 1;
  uint64_t elapsed_nanos = 0;
  constexpr uint64_t kNanosPerMilli = 1000000;
  for (num_iterations_in_1ms = 1; elapsed_nanos < kNanosPerMilli;
       num_iterations_in_1ms <<= 1) {
    const uint64_t start_nanos = GetThreadVirtualTimeNano();
    for (size_t i = 0; i < num_iterations_in_1ms; ++i) {
      do_one_iteration(i, aligned_size);
    }
    elapsed_nanos = GetThreadVirtualTimeNano() - start_nanos;
  }

  // Benchmark for about 1 seconds.
  constexpr uint64_t kNanosPerSec = 1000000000;
  const double estimated_nanos_per_iterations =
      static_cast<double>(elapsed_nanos) / num_iterations_in_1ms;
  size_t num_iterations_in_1s = kNanosPerSec / estimated_nanos_per_iterations;
  const uint64_t benchmark_start_nanos = GetThreadVirtualTimeNano();
  for (size_t i = 0; i < num_iterations_in_1s; ++i) {
    do_one_iteration(i, aligned_size);
  }
  const uint64_t benchmark_end_nanos = GetThreadVirtualTimeNano();
  const double benchmarks_elapsed_secs =
      static_cast<double>(benchmark_end_nanos - benchmark_start_nanos) /
      kNanosPerSec;

  // Return bandwidth as bytes per seconds.
  return static_cast<uint64_t>(aligned_size * num_iterations_in_1s /
                               benchmarks_elapsed_secs);
}

// Returns bandwidth in byte pairs compared per second for a memory comparison
// function. The actual memory bandwidth is about double of that because we need
// to read from two memory ranges.
uint64_t MeasureCompareBandwidth(MemoryCompareFunc func, size_t size) {
  auto do_one_iteration = [&func](size_t i, size_t size) {
    bool result = func(test_buffer_1, test_buffer_2, size);
    // Use a dummy assembly statement to avoid the call above being
    // optimized away.
    asm volatile("" : : "m"(result));
    CHECK(result);
  };
  return MeasureBandwidth(do_one_iteration, size);
}

template <typename MemoryCompareFunc>
void RunBenchmark(uint64_t (*measure)(MemoryCompareFunc, size_t),
                  const char* func_name, MemoryCompareFunc func) {
  constexpr size_t kTestSizes[] = {(1 << 4), (1 << 8), (1 << 12), (1 << 16),
                                   (1 << 20)};
  constexpr size_t kNumTestSizes = sizeof(kTestSizes) / sizeof(kTestSizes[0]);

  LOG_INFO("Benchmarking ", func_name);
  for (int i = 0; i < kNumTestSizes; ++i) {
    const size_t size = kTestSizes[i];
    const uint64_t bandwidth_mibps = (*measure)(func, size) / (1 << 20);
    LOG_INFO(IntStr(size), "B : ", IntStr(bandwidth_mibps), " MiB/s");
  }
}

void RunCompareBenchmark(const char* func_name, MemoryCompareFunc func) {
  RunBenchmark(MeasureCompareBandwidth, func_name, func);
}

// Returns bandwidth in bytes copied per second for a memory copying function.
// The raw memory bandwidth is about double of that because we need to
// access two memory ranges for each byte copied.
uint64_t MeasureCopyBandwidth(MemoryCopyFunc func, size_t size) {
  auto do_one_iteration = [&func](size_t i, size_t size) {
    func(test_buffer_1, test_buffer_2, size);
  };
  return MeasureBandwidth(do_one_iteration, size);
}

void RunCopyBenchmark(const char* func_name, MemoryCopyFunc func) {
  RunBenchmark(MeasureCopyBandwidth, func_name, func);
}

// Returns bandwidth in bytes set per second for a memory setting function.
uint64_t MeasureSetBandwidth(MemorySetFunc func, size_t size) {
  auto do_one_iteration = [&func](size_t i, size_t size) {
    func(test_buffer_1, 0, size);
  };
  return MeasureBandwidth(do_one_iteration, size);
}

void RunSetBenchmark(const char* func_name, MemorySetFunc func) {
  RunBenchmark(MeasureSetBandwidth, func_name, func);
}

// Returns bandwidth in bytes processed per second for a memory all equal to
// function.
uint64_t MeasureAllEqualToBandwidth(MemoryAllEqualToFunc func, size_t size) {
  CHECK_LE(size, BUFFER_SIZE);
  size_t aligned_size = RoundUp(size, sizeof(uint64_t));
  memset(test_buffer_1, 0, aligned_size);

  auto do_one_iteration = [&func](size_t i, size_t size) {
    func(test_buffer_1, 0, size);
  };
  return MeasureBandwidth(do_one_iteration, size);
}

void RunAllEqualToBenchmark(const char* func_name, MemoryAllEqualToFunc func) {
  RunBenchmark(MeasureAllEqualToBandwidth, func_name, func);
}

int BenchmarkMain() {
  RunCompareBenchmark("MemEq", MemEq);
  RunCompareBenchmark("bcmp", BcmpAdaptor);
  RunCompareBenchmark("MemEqSSE", MemEqSSE);
  RunCopyBenchmark("MemCopy", MemCopy);
  RunCopyBenchmark("memcpy", MemcpyAdaptor);
  RunSetBenchmark("MemSet", MemSet);
  RunSetBenchmark("memset", NolibcMemsetAdaptor);
  RunAllEqualToBenchmark("MemAllEqualTo", MemAllEqualTo);
  return 0;
}

}  // namespace

}  // namespace silifuzz

int main() { return silifuzz::BenchmarkMain(); }
