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
// I<DATE> <PID> mem_util_benchmark.cc:307] Benchmarking MemEq
// I<DATE> <PID> mem_util_benchmark.cc:317] 16B : 4948 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 256B : 27627 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 4096B : 36567 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 65536B : 39640 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 1048576B : 39759 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:307] Benchmarking bcmp
// I<DATE> <PID> mem_util_benchmark.cc:317] 16B : 1705 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 256B : 1942 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 4096B : 2055 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 65536B : 2074 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 1048576B : 2071 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:307] Benchmarking MemEqSSE
// I<DATE> <PID> mem_util_benchmark.cc:317] 16B : 6804 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 256B : 32070 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 4096B : 37148 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 65536B : 39668 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 1048576B : 39901 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:307] Benchmarking MemEqAVX512F
// I<DATE> <PID> mem_util_benchmark.cc:317] 16B : 4999 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 256B : 66726 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 4096B : 98419 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 65536B : 99548 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 1048576B : 88612 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:307] Benchmarking MemCopy
// I<DATE> <PID> mem_util_benchmark.cc:317] 16B : 4158 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 256B : 32667 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 4096B : 44138 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 65536B : 37012 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 1048576B : 32882 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:307] Benchmarking MemCopyAVX512F
// I<DATE> <PID> mem_util_benchmark.cc:317] 16B : 5457 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 256B : 51237 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 4096B : 84638 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 65536B : 43387 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 1048576B : 35165 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:307] Benchmarking memcpy
// I<DATE> <PID> mem_util_benchmark.cc:317] 16B : 4541 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 256B : 33758 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 4096B : 46035 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 65536B : 37700 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 1048576B : 32881 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:307] Benchmarking MemSet
// I<DATE> <PID> mem_util_benchmark.cc:317] 16B : 5458 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 256B : 43675 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 4096B : 48823 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 65536B : 35159 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 1048576B : 32853 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:307] Benchmarking MemSetAVX512F
// I<DATE> <PID> mem_util_benchmark.cc:317] 16B : 5510 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 256B : 54429 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 4096B : 84500 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 65536B : 43412 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 1048576B : 33149 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:307] Benchmarking memset
// I<DATE> <PID> mem_util_benchmark.cc:317] 16B : 4889 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 256B : 31370 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 4096B : 45330 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 65536B : 33595 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 1048576B : 32885 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:307] Benchmarking MemAllEqualTo
// I<DATE> <PID> mem_util_benchmark.cc:317] 16B : 3839 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 256B : 29551 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 4096B : 40534 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 65536B : 44601 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 1048576B : 35512 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:307] Benchmarking MemAllEqualToZero
// I<DATE> <PID> mem_util_benchmark.cc:317] 16B : 4953 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 256B : 37840 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 4096B : 48527 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 65536B : 47900 MiB/s
// I<DATE> <PID> mem_util_benchmark.cc:317] 1048576B : 37038 MiB/s

//
#include <cstdint>
#include <cstring>
#ifdef __x86_64__
#include <immintrin.h>
#endif

#include "third_party/lss/lss/linux_syscall_support.h"
#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/math.h"
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

#ifdef __x86_64__
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

// Returns bandwidth in bytes processed per second for a memory function.
// function.
template <typename MemoryCompareFunc>
inline uint64_t MeasureBandwidth(void (*do_one_iteration)(MemoryCompareFunc,
                                                          size_t),
                                 MemoryCompareFunc func, size_t size) {
  CHECK_LE(size, BUFFER_SIZE);

  size_t aligned_size = RoundUpToPowerOfTwo(size, sizeof(uint64_t));

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
                  bool should_memset = false, uint8_t memset_value = 0) {
  constexpr size_t kTestSizes[] = {(1 << 4), (1 << 8), (1 << 12), (1 << 16),
                                   (1 << 20)};
  constexpr size_t kNumTestSizes = sizeof(kTestSizes) / sizeof(kTestSizes[0]);

  LOG_INFO("Benchmarking ", func_name);
  for (int i = 0; i < kNumTestSizes; ++i) {
    const size_t size = kTestSizes[i];
    if (should_memset) {
      CHECK_LE(size, BUFFER_SIZE);
      size_t aligned_size = RoundUpToPowerOfTwo(size, sizeof(uint64_t));
      memset(test_buffer_1, memset_value, aligned_size);
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

// Checks that size bytes of a test buffer are equal to 1.
void AllEqualToNonZeroOneIteration(MemoryAllEqualToFunc func, size_t size) {
  func(test_buffer_1, 1, size);
}

// Checks that size bytes of a test buffer are equal to 0.
void AllEqualToZeroOneIteration(MemoryAllEqualToFunc func, size_t size) {
  func(test_buffer_1, 0, size);
}

int BenchmarkMain() {
  // Measures bandwidth in byte pairs compared per second for a memory
  // comparison function. The actual memory bandwidth is about double of that
  // because we need to read from two memory ranges.
  RunBenchmark(CompareOneIteration, "MemEq", MemEq);
  RunBenchmark(CompareOneIteration, "bcmp", BcmpAdaptor);
#ifdef __x86_64__
  RunBenchmark(CompareOneIteration, "MemEqSSE", MemEqSSE);
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
  RunBenchmark(AllEqualToNonZeroOneIteration, "MemAllEqualTo", MemAllEqualTo,
               /*should_memset=*/true, /*memset_value=*/1);

  // Measures bandwidth in bytes processed per second for a memory all equal to
  // function for the special case of 0.
  RunBenchmark(AllEqualToZeroOneIteration, "MemAllEqualToZero", MemAllEqualTo,
               /*should_memset=*/true, /*memset_value=*/0);

  return 0;
}

}  // namespace

}  // namespace silifuzz

int main() { return silifuzz::BenchmarkMain(); }
