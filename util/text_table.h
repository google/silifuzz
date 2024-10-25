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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_TEXT_TABLE_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_TEXT_TABLE_H_

#include <stddef.h>

#include <cstddef>
#include <functional>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"

namespace silifuzz {

// A simple class to help format text tables.
//
// This class is thread-compatible.
class TextTable {
 public:
  // In-cell horizontal alignment choices.
  enum Align : char { kLeft = 'l', kRight = 'r', kCenter = 'c' };

  // The line printing/output function.
  using Printer = std::function<void(absl::string_view text_line)>;

  // CAVEAT: The number of columns for this table will be set by the first
  // Set*() or Add*() call. Subsequent such calls must be consistent.
  TextTable();

  // Intentionally movable and copyable.

  // Returns *this to the post-construction state.
  void Reset() { *this = TextTable(); }

  // Sets separators between all columns.
  // By default spaces are used.
  void SetSeparators(absl::Span<const absl::string_view> separators);

  // Sets alignment for all columns; values of Align enum are supported.
  // By default kLeft is used.
  void SetAligns(absl::Span<const char> aligns);

  // Adds a row of table cells.
  void AddRow(absl::Span<const absl::string_view> cell_values);

  // Convenient variant of AddRow() that converts its args via absl::StrCat().
  template <typename... Ts>
  void AddRowCells(Ts&&... cell_values) {
    std::vector<std::string> row(
        {absl::StrCat(std::forward<Ts>(cell_values))...});
    AddRow(std::vector<absl::string_view>(row.begin(), row.end()));
  }

  // Prints current state of *this via line_printer.
  void PrintVia(Printer line_printer) const;

 private:
  // Initializes (or verifies) *this to wowk with num_columns.
  void Init(int num_columns);

  int num_columns_;
  std::vector<std::string> separators_;  // num_columns_-1 size
  std::vector<Align> aligns_;            // num_columns_ size
  std::vector<std::size_t> widths_;      // num_columns_ size
  using Row = std::vector<std::string>;  // num_columns_ size
  std::vector<Row> rows_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_TEXT_TABLE_H_
