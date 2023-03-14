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
// I<DATE> <PID> mem_util_benchmark.cc:300] Benchmarking MemEq
// I<DATE> <PID> mem_util_benchmark.cc:310] 16B : 4235 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 256B : 19605 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 4096B : 20647 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 65536B : 21401 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 1048576B : 21435 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:300] Benchmarking bcmp
// I<DATE> <PID> mem_util_benchmark.cc:310] 16B : 1709 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 256B : 1899 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 4096B : 2023 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 65536B : 2022 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 1048576B : 2036 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:300] Benchmarking MemEqSSE
// I<DATE> <PID> mem_util_benchmark.cc:310] 16B : 9306 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 256B : 18131 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 4096B : 18081 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 65536B : 17807 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 1048576B : 18278 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:300] Benchmarking MemEqAVX512F
// I<DATE> <PID> mem_util_benchmark.cc:310] 16B : 4438 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 256B : 60006 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 4096B : 95925 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 65536B : 97082 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 1048576B : 86545 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:300] Benchmarking MemCopy
// I<DATE> <PID> mem_util_benchmark.cc:310] 16B : 5168 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 256B : 20109 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 4096B : 23400 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 65536B : 21326 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 1048576B : 20786 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:300] Benchmarking MemCopyAVX512F
// I<DATE> <PID> mem_util_benchmark.cc:310] 16B : 5406 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 256B : 50265 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 4096B : 82962 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 65536B : 37237 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 1048576B : 35203 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:300] Benchmarking memcpy
// I<DATE> <PID> mem_util_benchmark.cc:310] 16B : 1996 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 256B : 2215 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 4096B : 2431 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 65536B : 2446 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 1048576B : 2444 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:300] Benchmarking MemSet
// I<DATE> <PID> mem_util_benchmark.cc:310] 16B : 4455 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 256B : 23776 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 4096B : 24423 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 65536B : 21575 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 1048576B : 20751 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:300] Benchmarking MemSetAVX512F
// I<DATE> <PID> mem_util_benchmark.cc:310] 16B : 4882 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 256B : 53834 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 4096B : 82968 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 65536B : 39340 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 1048576B : 31784 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:300] Benchmarking memset
// I<DATE> <PID> mem_util_benchmark.cc:310] 16B : 2031 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 256B : 2773 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 4096B : 3035 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 65536B : 2794 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 1048576B : 2783 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:300] Benchmarking MemAllEqualTo
// I<DATE> <PID> mem_util_benchmark.cc:310] 16B : 4454 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 256B : 21752 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 4096B : 25574 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 65536B : 23994 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:310] 1048576B : 22620 MiB/s
//
#include <cstdint>
#include <cstring>
#ifdef __x86_64__
#include <immintrin.h>
#endif

#include "third_party/lss/lss/linux_syscall_support.h"
#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/mem_util.h"

#ifdef __x86_64__
#include "./util/avx.h"

// This file is compiled with "-mno-sse" by default. So we have to force
// AVX512F target via a function attribute.
#define AVX512F_FUNCTION __attribute__((target("avx512f")))

#endif

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

#ifdef __x86_64__
AVX512F_FUNCTION void MemCopyAVX512F(void* dest, const void* src, size_t n) {
  // Optimize only if n is 8-byte aligned.
  uint8_t* dest_u8 = reinterpret_cast<uint8_t*>(dest);
  const uint8_t* src_u8 = reinterpret_cast<const uint8_t*>(src);
  if (n % sizeof(uint64_t) != 0) {
    for (size_t i = 0; i < n; ++i) {
      dest_u8[i] = src_u8[i];
    }
    return;
  }

  size_t i;
  for (i = 0; i < n; i += sizeof(__m512i)) {
    _mm512_storeu_epi64(&dest_u8[i], _mm512_loadu_epi64(&src_u8[i]));
  }

  if (i < n) {
    const size_t remaining_u64s = (n - i) / sizeof(uint64_t);
    const __mmask16 mask = _cvtu32_mask16((1 << remaining_u64s) - 1);
    _mm512_mask_storeu_epi64(&dest_u8[i], mask, _mm512_loadu_epi64(&src_u8[i]));
  }
}

AVX512F_FUNCTION void MemSetAVX512F(void* dest, uint8_t c, size_t n)
    __attribute__((no_builtin("memset"))) /* see MemCopy() above */ {
  uint8_t* dest_u8 = reinterpret_cast<uint8_t*>(dest);
  // Optimize only if n is both 8-byte aligned.
  if (n % sizeof(uint64_t) != 0) {
    for (size_t i = 0; i < n; ++i) {
      dest_u8[i] = c;
    }
    return;
  }

  const __m512i c_m512i = _mm512_set1_epi8(c);
  size_t i;
  for (i = 0; i < n; i += sizeof(__m512i)) {
    _mm512_storeu_epi64(&dest_u8[i], c_m512i);
  }

  if (i < n) {
    const size_t remaining_u64s = (n - i) / sizeof(uint64_t);
    const __mmask16 mask = _cvtu32_mask16((1 << remaining_u64s) - 1);
    _mm512_mask_storeu_epi64(&dest_u8[i], mask, c_m512i);
  }
}

AVX512F_FUNCTION bool MemEqAVX512F(const void* s1, const void* s2, size_t n)
    __attribute__((no_builtin("memcmp"))) {
  // Optimize only if n is 8-byte aligned.
  if (n % sizeof(uint64_t) != 0) {
    return bcmp(s1, s2, n) == 0;
  }
  const char* char_ptr1 = reinterpret_cast<const char*>(s1);
  const char* char_ptr2 = reinterpret_cast<const char*>(s2);

  // Accumulate XOR differences. diff is non-zero is there are any pairs of
  // different corresponding bits in s1 and s2.
  const __m512i kZeros = _mm512_setzero_epi32();
  __m512i diff = kZeros;

  size_t i;
  for (i = 0; i < n; i += sizeof(__m512i)) {
    diff = _mm512_or_epi64(diff,
                           _mm512_xor_epi64(_mm512_loadu_epi64(&char_ptr1[i]),
                                            _mm512_loadu_epi64(&char_ptr2[i])));
  }

  if (i < n) {
    const size_t remaining_epi64s = (n - i) / sizeof(uint64_t);
    const __mmask16 mask = _cvtu32_mask16((1L << remaining_epi64s) - 1);
    const __m512i remainder1 = _mm512_maskz_loadu_epi64(mask, &char_ptr1[i]);
    const __m512i remainder2 = _mm512_maskz_loadu_epi64(mask, &char_ptr2[i]);
    diff = _mm512_or_epi64(diff, _mm512_xor_epi64(remainder1, remainder2));
  }

  return _mm512_cmpeq_epi64_mask(diff, kZeros) == static_cast<__mmask8>(~0);
}
#endif

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
template <typename MemoryCompareFunc>
inline uint64_t MeasureBandwidth(void (*do_one_iteration)(MemoryCompareFunc,
                                                          size_t),
                                 MemoryCompareFunc func, size_t size) {
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
      do_one_iteration(func, aligned_size);
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
    do_one_iteration(func, aligned_size);
  }
  const uint64_t benchmark_end_nanos = GetThreadVirtualTimeNano();
  const double benchmarks_elapsed_secs =
      static_cast<double>(benchmark_end_nanos - benchmark_start_nanos) /
      kNanosPerSec;

  // Return bandwidth as bytes per seconds.
  return static_cast<uint64_t>(aligned_size * num_iterations_in_1s /
                               benchmarks_elapsed_secs);
}

template <typename MemoryCompareFunc>
void RunBenchmark(void (*do_one_iteration)(MemoryCompareFunc, size_t),
                  const char* func_name, MemoryCompareFunc func,
                  bool should_memset = false) {
  constexpr size_t kTestSizes[] = {(1 << 4), (1 << 8), (1 << 12), (1 << 16),
                                   (1 << 20)};
  constexpr size_t kNumTestSizes = sizeof(kTestSizes) / sizeof(kTestSizes[0]);

  LOG_INFO("Benchmarking ", func_name);
  for (int i = 0; i < kNumTestSizes; ++i) {
    const size_t size = kTestSizes[i];
    if (should_memset) {
      CHECK_LE(size, BUFFER_SIZE);
      size_t aligned_size = RoundUp(size, sizeof(uint64_t));
      memset(test_buffer_1, 0, aligned_size);
    }
    const uint64_t bandwidth_mibps =
        MeasureBandwidth(do_one_iteration, func, size) / (1 << 20);
    LOG_INFO(IntStr(size), "B : ", IntStr(bandwidth_mibps), " MiB/s");
  }
}

// Compares size bytes between the two test buffers.
void CompareOneIteration(MemoryCompareFunc func, size_t size) {
  bool result = func(test_buffer_1, test_buffer_2, size);
  // Use a dummy assembly statement to avoid the call above being
  // optimized away.
  asm volatile("" : : "m"(result));
  CHECK(result);
}

// Copies size bytes from one test buffer to the other.
void CopyOneIteration(MemoryCopyFunc func, size_t size) {
  func(test_buffer_1, test_buffer_2, size);
}

// Sets size bytes in a test buffer to 0.
void SetOneIteration(MemorySetFunc func, size_t size) {
  func(test_buffer_1, 0, size);
}

// Checks that size bytes of a test buffer are equal to 0.
void AllEqualToOneIteration(MemoryAllEqualToFunc func, size_t size) {
  func(test_buffer_1, 0, size);
}

int BenchmarkMain() {
  // Measures bandwidth in byte pairs compared per second for a memory
  // comparison function. The actual memory bandwidth is about double of that
  // because we need to read from two memory ranges.
  RunBenchmark(CompareOneIteration, "MemEq", MemEq);
  RunBenchmark(CompareOneIteration, "bcmp", BcmpAdaptor);
  RunBenchmark(CompareOneIteration, "MemEqSSE", MemEqSSE);
#ifdef __x86_64__
  if (HasAVX512Registers()) {
    RunBenchmark(CompareOneIteration, "MemEqAVX512F", MemEqAVX512F);
  }
#endif

  // Measures bandwidth in bytes copied per second for a memory copying
  // function. The raw memory bandwidth is about double of that because we need
  // to access two memory ranges for each byte copied.
  RunBenchmark(CopyOneIteration, "MemCopy", MemCopy);
#ifdef __x86_64__
  if (HasAVX512Registers()) {
    RunBenchmark(CopyOneIteration, "MemCopyAVX512F", MemCopyAVX512F);
  }
#endif
  RunBenchmark(CopyOneIteration, "memcpy", MemcpyAdaptor);

  // Measures bandwidth in bytes set per second for a memory setting function.
  RunBenchmark(SetOneIteration, "MemSet", MemSet);
#ifdef __x86_64__
  if (HasAVX512Registers()) {
    RunBenchmark(SetOneIteration, "MemSetAVX512F", MemSetAVX512F);
  }
#endif
  RunBenchmark(SetOneIteration, "memset", NolibcMemsetAdaptor);

  // Measures bandwidth in bytes processed per second for a memory all equal to
  // function.
  RunBenchmark(AllEqualToOneIteration, "MemAllEqualTo", MemAllEqualTo,
               /*should_memset=*/true);
  return 0;
}

}  // namespace

}  // namespace silifuzz

int main() { return silifuzz::BenchmarkMain(); }
