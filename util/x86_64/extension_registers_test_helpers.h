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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_X86_64_REGISTERS_TEST_HELPERS_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_X86_64_REGISTERS_TEST_HELPERS_H_

#include <x86intrin.h>

#include <cstdint>

// The test helpers exercise extension registers access functions. These
// require very precise control of register access and must be done in
// assembly to avoid compilers generating code accessing those registers
// at the same time.

// Put the helpers in "C" namespace to avoid name-mangling.
extern "C" {

void XMMSaveTestHelper(__m128* output);
void XMMRoundTripTestHelper(const __m128* input, __m128* output);
void XMMClearTestHelper(const __m128* input, __m128* output);

void YMMSaveTestHelper(__m256* output);
void YMMRoundTripTestHelper(const __m256* input, __m256* output);
void YMMClearTestHelper(const __m256* input, __m256* output);

void ZMMSaveTestHelper(__m512 output[32]);
void ZMMRoundTripTestHelper(const __m512* input, __m512* output);
void ZMMClearTestHelper(const __m512* input, __m512* output);

void Opmask16SaveTestHelper(uint16_t* output);
void Opmask16RoundTripTestHelper(const uint16_t* input, uint16_t* output);
void Opmask16ClearTestHelper(const uint16_t* input, uint16_t* output);

void Opmask64SaveTestHelper(uint64_t* output);
void Opmask64RoundTripTestHelper(const uint64_t* input, uint64_t* output);
void Opmask64ClearTestHelper(const uint64_t* input, uint64_t* output);
}

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_X86_64_REGISTERS_TEST_HELPERS_H_
