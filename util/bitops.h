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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_BITOPS_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_BITOPS_H_

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>

namespace silifuzz {

// WARNING: the functions in this file treat the contents of data structures as
// raw bits. The user is responsible for making sure this is a meaningful
// operation. For instance, struct padding must be zeroed. For instance, there
// should not be any pointers in the data structure. If refactoring introduces
// pointers into a data structure your are performing bitops on, the code will
// silently start behaving badly. Be careful.

// Number of bits contained in type T.
template <typename T>
inline constexpr size_t NumBits() {
  return sizeof(T) * 8;
}

// Convenience function to infer the template type from a variable.
template <typename T>
inline constexpr size_t NumBits(const T& a) {
  return NumBits<T>();
}

namespace bitops_internal {

// The function determines the largest integral integer type with a size that
// is an exact multiple of the specified size N. This is the largest granularity
// we can work at while looping over the data.
// In general, the internal bitops functions are specialized in terms of the
// exact size of data being processed so that we can select the best granularity
// and also allow the compiler to optimize a fixed-iteration loop.
// For small amounts of data (N=8, for example) the generated code is
// more-or-less what you'd write by hand (XOR two 64-bit values, for example).
// In a perfect world we wouldn't need to explictly select the granularity and
// rely on pure compiler optimization, but currently the compiler doesn't always
// get there wihtout a little help
template <size_t N>
inline constexpr auto BestIntType() {
  if constexpr (N % sizeof(uint64_t) == 0) {
    return uint64_t{};
  } else if constexpr (N % sizeof(uint32_t) == 0) {
    return uint32_t{};
  } else if constexpr (N % sizeof(uint16_t) == 0) {
    return uint16_t{};
  } else {
    return uint8_t{};
  }
}

// Note: most of the internal functions in this file use "memcpy". This may look
// a little strange for code that is otherwise designed to run fast. In
// practice, the compiler does a very good job of optimizing out calls to memcpy
// with a small, fixed size, so none of these calls show up in the generated
// code. So why write the code this way if they are optimized out? The root
// cause is that we want to process arbitrary datatypes as if they were arrays
// of integers so that we can have direct access to the bits. Unfortunately the
// C/C++ strict aliasing rule means that casting a pointer to an arbitrary
// datatype to a pointer to an array of integers can cause undefined behavior
// unless it is an array of bytes. Doing bit operations at the byte level leaves
// performance on the table, however, and the optimizer cannot always fuse the
// operations on bytes into operations on larger words. So - how do we operate
// on larger words without running afoul of strict aliasing? The answer is that
// we treat the data as an array of bytes and then memcpy the larger words in
// and out of those bytes. The compiler will then optimize the memcpys into
// simple loads and stores. Effectively we're operating on arrays of
// arbitrary-sized integers without running into strict aliasing issues.

// Calculate the population count for a `n` byte block of memory.
template <typename Granularity>
size_t PopCount(size_t n, const void* bitmap) {
  const uint8_t* bytes = reinterpret_cast<const uint8_t*>(bitmap);
  size_t count = 0;
  for (size_t i = 0; i < n; i += sizeof(Granularity)) {
    Granularity tmp;
    // See notes in the file on memcpy.
    memcpy(&tmp, &bytes[i], sizeof(Granularity));
    // Using a 64-bit popcount for small granularities is a bit hacky, but it's
    // close enough.
    count += __builtin_popcountll(tmp);
  }
  return count;
}

// Calculate "result = a ^ b" for a `n` byte block of memory.
template <typename Granularity>
void BitDiff(size_t n, const void* a, const void* b, void* result) {
  const uint8_t* a_bytes = reinterpret_cast<const uint8_t*>(a);
  const uint8_t* b_bytes = reinterpret_cast<const uint8_t*>(b);
  uint8_t* result_bytes = reinterpret_cast<uint8_t*>(result);

  for (size_t i = 0; i < n; i += sizeof(Granularity)) {
    Granularity a_tmp, b_tmp, result_tmp;
    // See notes in the file on memcpy.
    memcpy(&a_tmp, &a_bytes[i], sizeof(Granularity));
    memcpy(&b_tmp, &b_bytes[i], sizeof(Granularity));
    result_tmp = a_tmp ^ b_tmp;
    memcpy(&result_bytes[i], &result_tmp, sizeof(Granularity));
  }
}

// Incrementally calculate bit toggles for a `n` byte block of memory.
template <typename Granularity>
void AccumulateToggle(size_t n, const void* a, const void* b, void* zero_one,
                      void* one_zero) {
  const uint8_t* a_bytes = reinterpret_cast<const uint8_t*>(a);
  const uint8_t* b_bytes = reinterpret_cast<const uint8_t*>(b);
  uint8_t* zero_one_bytes = reinterpret_cast<uint8_t*>(zero_one);
  uint8_t* one_zero_bytes = reinterpret_cast<uint8_t*>(one_zero);

  for (size_t i = 0; i < n; i += sizeof(Granularity)) {
    Granularity a_tmp, b_tmp, zero_one_tmp, one_zero_tmp;
    // See notes in the file on memcpy.
    memcpy(&a_tmp, &a_bytes[i], sizeof(Granularity));
    memcpy(&b_tmp, &b_bytes[i], sizeof(Granularity));
    memcpy(&zero_one_tmp, &zero_one_bytes[i], sizeof(Granularity));
    memcpy(&one_zero_tmp, &one_zero_bytes[i], sizeof(Granularity));
    zero_one_tmp |= ~a_tmp & b_tmp;
    one_zero_tmp |= a_tmp & ~b_tmp;
    memcpy(&zero_one_bytes[i], &zero_one_tmp, sizeof(Granularity));
    memcpy(&one_zero_bytes[i], &one_zero_tmp, sizeof(Granularity));
  }
}

// Invoke a callback for each bit in `n` bytes.
template <typename Granularity, typename F>
inline void ForEachBit(size_t n, const void* bitmap, F f) {
  const uint8_t* bytes = reinterpret_cast<const uint8_t*>(bitmap);

  for (size_t i = 0; i < n; i += sizeof(Granularity)) {
    Granularity tmp;
    memcpy(&tmp, &bytes[i], sizeof(Granularity));
    for (size_t bit = 0; bit < NumBits<Granularity>(); ++bit) {
      const Granularity mask = (Granularity)1 << bit;
      f(i * 8 + bit, !!(tmp & mask));
    }
  }
}

// Invoke a callback for each bit in `n` bytes that is one.
template <typename Granularity, typename F>
inline void ForEachSetBit(size_t n, const void* bitmap, F f) {
  const uint8_t* bytes = reinterpret_cast<const uint8_t*>(bitmap);

  for (size_t i = 0; i < n; i += sizeof(Granularity)) {
    Granularity tmp;
    memcpy(&tmp, &bytes[i], sizeof(Granularity));
    // For sparse bitmaps, ForEachSetBit can be significantly faster than
    // ForEachBit because we can efficiently check if all the bits in the
    // granule are zero and skip the inner loop.
    if (tmp) {
      for (size_t bit = 0; bit < NumBits<Granularity>(); ++bit) {
        const Granularity mask = (Granularity)1 << bit;
        if (tmp & mask) {
          f(i * 8 + bit);
        }
      }
    }
  }
}

// Invoke a callback for each bit in `n` bytes that is different.
template <typename Granularity, typename F>
inline void ForEachDiffBit(size_t n, const void* a, const void* b, F f) {
  const uint8_t* a_bytes = reinterpret_cast<const uint8_t*>(a);
  const uint8_t* b_bytes = reinterpret_cast<const uint8_t*>(b);

  for (size_t i = 0; i < n; i += sizeof(Granularity)) {
    Granularity a_tmp, b_tmp, diff;
    memcpy(&a_tmp, &a_bytes[i], sizeof(Granularity));
    memcpy(&b_tmp, &b_bytes[i], sizeof(Granularity));
    diff = a_tmp ^ b_tmp;
    // Optimize for sparsity by checking if all the bits are zero.
    if (diff) {
      for (size_t bit = 0; bit < NumBits<Granularity>(); ++bit) {
        const Granularity mask = (Granularity)1 << bit;
        if (diff & mask) {
          f(i * 8 + bit, !!(b_tmp & mask));
        }
      }
    }
  }
}

#define APPLY_WITH_BEST_INT_TYPE(func, byte_size, ...)                 \
  [&](size_t n, auto&&... args) {                                      \
    if (n % 8 == 0) {                                                  \
      return func<uint64_t>(n, std::forward<decltype(args)>(args)...); \
    } else if (n % 4 == 0) {                                           \
      return func<uint32_t>(n, std::forward<decltype(args)>(args)...); \
    } else if (n % 2 == 0) {                                           \
      return func<uint16_t>(n, std::forward<decltype(args)>(args)...); \
    } else {                                                           \
      return func<uint8_t>(n, std::forward<decltype(args)>(args)...);  \
    }                                                                  \
  }(byte_size, ##__VA_ARGS__)

}  // namespace bitops_internal

// Zeros the struct. Slightly nicer than calling memset directly.
template <typename T>
void ClearBits(T& result) {
  memset(&result, 0, sizeof(result));
}

// Counts the number of bits that have been set in the struct.
// Assumes that struct padding of the input has been zeroed.
template <typename T>
size_t PopCount(const T& bitmap) {
  using Granularity = decltype(bitops_internal::BestIntType<sizeof(T)>());
  return bitops_internal::PopCount<Granularity>(sizeof(T), &bitmap);
}

// Create a bitmask in `result` that shows the bits that differ between `a` and
// `b`.
// Assumes that struct padding of the inputs has been zeroed.
template <typename T>
void BitDiff(const T& a, const T& b, T& result) {
  using Granularity = decltype(bitops_internal::BestIntType<sizeof(T)>());
  return bitops_internal::BitDiff<Granularity>(sizeof(T), &a, &b, &result);
}

// Compute which bits have changed between `a` and `b` as well as the direction
// of the change. If a bit is 0 in `a` and 1 in `b`, set that bit in `zero_one`.
// Similarly, if a bit is 1 in `a` and 0 in `b`, set that bit in `one_zero`. If
// a bit has not changed between a and b, do not modify the bit in the output
// structs. This function can be called multiple times with different (a, b)
// input pairs but the same (zero_one, one_zero) output pair to track if a bit
// has ever toggled throughout a sequence of input pairs. The output pair should
// be explicitly cleared before calling this function since this function will
// only ever set output bits and never clear them.
// Assumes that struct padding of the inputs has been zeroed.
template <typename T>
void AccumulateToggle(const T& a, const T& b, T& zero_one, T& one_zero) {
  using Granularity = decltype(bitops_internal::BestIntType<sizeof(T)>());
  bitops_internal::AccumulateToggle<Granularity>(sizeof(T), &a, &b, &zero_one,
                                                 &one_zero);
}

// Note: the following functions invoke callbacks where one of the arguments is
// the "index" of the bit. On little endian systems, the index of a bit is the
// number of bits between that particular bit and the start of the data
// structure, assuming the bits in each byte are traversed from least
// significant to most significant. On big endian systems the optimization that
// groups bytes into larger granules means the bytes within a granule are
// effectively swapped when iterating and calculating the index, but fixing that
// isn't worth the extra code, currently.
// In general it's best to assume the index is a unique name for the bit and not
// to assume it has any particular meaning or any guarentee it will have the
// same value in the future.

// Call `f` for ever bit in `bitmap`.
// The first argument of `f` is the index of the bit.
// The second argument of `f` is the value of the bit in `bitmap`.
template <typename T, typename F>
inline void ForEachBit(const T& bitmap, F f) {
  using Granularity = decltype(bitops_internal::BestIntType<sizeof(T)>());
  bitops_internal::ForEachBit<Granularity, F>(sizeof(T), &bitmap, f);
}

// Call `f` for ever bit in `bitmap` that is set.
// The only argument of `f` is index of the bit.
template <typename T, typename F>
inline void ForEachSetBit(const T& bitmap, F f) {
  using Granularity = decltype(bitops_internal::BestIntType<sizeof(T)>());
  bitops_internal::ForEachSetBit<Granularity, F>(sizeof(T), &bitmap, f);
}

// Call `f` for ever bit that differs between `a` and `b`.
// The first argument of `f` is the index of the bit that differs.
// The second argument of `f` is the value of the bit in `b`.
template <typename T, typename F>
inline void ForEachDiffBit(const T& a, const T& b, F f) {
  using Granularity = decltype(bitops_internal::BestIntType<sizeof(T)>());
  bitops_internal::ForEachDiffBit<Granularity, F>(sizeof(T), &a, &b, f);
}

// ============================================================================
// An invariant of above BitOps that takes pointers to the byte arrays and their
// size as the input/output data types.

inline size_t PopCount(const void* bitmap, size_t byte_size) {
  return APPLY_WITH_BEST_INT_TYPE(bitops_internal::PopCount, byte_size, bitmap);
}

inline void BitDiff(const void* a, const void* b, size_t byte_size,
                    void* result) {
  return APPLY_WITH_BEST_INT_TYPE(bitops_internal::BitDiff, byte_size, a, b,
                                  result);
}

inline void AccumulateToggle(const void* a, const void* b, size_t byte_size,
                             void* zero_one, void* one_zero) {
  return APPLY_WITH_BEST_INT_TYPE(bitops_internal::AccumulateToggle, byte_size,
                                  a, b, zero_one, one_zero);
}

template <typename F>
inline void ForEachBit(const void* bitmap, size_t byte_size, F f) {
  return APPLY_WITH_BEST_INT_TYPE(bitops_internal::ForEachBit, byte_size,
                                  bitmap, f);
}

template <typename F>
inline void ForEachSetBit(const void* bitmap, size_t byte_size, F f) {
  return APPLY_WITH_BEST_INT_TYPE(bitops_internal::ForEachSetBit, byte_size,
                                  bitmap, f);
}

template <typename F>
inline void ForEachDiffBit(const void* a, const void* b, size_t byte_size,
                           F f) {
  return APPLY_WITH_BEST_INT_TYPE(bitops_internal::ForEachDiffBit, byte_size, a,
                                  b, f);
}

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_BITOPS_H_
