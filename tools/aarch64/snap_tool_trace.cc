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

#include "absl/status/status.h"
#include "./common/snapshot.h"
#include "./util/line_printer.h"
#include "./util/platform.h"

namespace silifuzz {

absl::Status Trace(const Snapshot& snapshot, PlatformId platform_id,
                   LinePrinter* line_printer) {
  return absl::UnimplementedError("Trace() Not implemented for AArch64");
}

}  // namespace silifuzz
