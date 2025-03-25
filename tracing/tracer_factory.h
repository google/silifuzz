// Copyright 2025 The SiliFuzz Authors.
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

#ifndef THIRD_PARTY_SILIFUZZ_TRACING_TRACER_FACTORY_H_
#define THIRD_PARTY_SILIFUZZ_TRACING_TRACER_FACTORY_H_

#include <memory>
#include <type_traits>

#include "./tracing/native_tracer.h"
#include "./tracing/tracer.h"
#include "./tracing/unicorn_tracer.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/itoa.h"

namespace silifuzz {

// Defines the type of tracers supported by this library.
enum class TracerType {
  kUnicorn = 0,
  kNative = 1,
};

// Makes EnumStr() works for TracerType.
template <>
inline constexpr const char* EnumNameMap<TracerType>[3] = {
    "unicorn",
    "native",
};

// Need static Arch check here because NativeTracer is linked only for the
// host's architecture.
template <typename Arch, std::enable_if_t<std::is_same_v<Arch, Host>, int> = 0>
std::unique_ptr<Tracer<Arch>> CreateNativeTracer() {
  return std::unique_ptr<Tracer<Arch>>(new NativeTracer());
}

template <typename Arch, std::enable_if_t<!std::is_same_v<Arch, Host>, int> = 0>
std::unique_ptr<Tracer<Arch>> CreateNativeTracer() {
  LOG_FATAL(
      "Native tracer error: requested architecture is different from host "
      "architecture.");
}

template <typename Arch>
std::unique_ptr<Tracer<Arch>> CreateTracer(TracerType type) {
  if (type == TracerType::kNative) {
    return CreateNativeTracer<Arch>();
  } else if (type == TracerType::kUnicorn) {
    return std::unique_ptr<Tracer<Arch>>(new UnicornTracer<Arch>());
  } else {
    LOG_FATAL("Unsupported tracer type: ", type);
  }
}

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_TRACING_TRACER_FACTORY_H_
