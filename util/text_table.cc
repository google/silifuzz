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

#include "./util/text_table.h"

#include "./util/checks.h"

namespace silifuzz {

TextTable::TextTable()
    : num_columns_(0), separators_(), aligns_(), widths_(), rows_() {}

void TextTable::Init(int num_columns) {
  if (num_columns_ != 0) {
    DCHECK_EQ(num_columns, num_columns_);
  } else {
    DCHECK_GT(num_columns, 0);
    num_columns_ = num_columns;
    separators_ = std::vector<std::string>(num_columns_ - 1, " ");
    aligns_ = std::vector<Align>(num_columns_, kLeft);
    widths_ = std::vector<size_t>(num_columns_, 0);
  }
}

void TextTable::SetSeparators(absl::Span<const absl::string_view> separators) {
  Init(separators.size() + 1);
  separators_ = std::vector<std::string>(separators.begin(), separators.end());
}

void TextTable::SetAligns(absl::Span<const char> aligns) {
  Init(aligns.size());
  int i = 0;
  for (auto a : aligns) {
    DCHECK(a == kLeft || a == kRight || a == kCenter);
    aligns_[i] = static_cast<Align>(a);
  }
}

void TextTable::AddRow(absl::Span<const absl::string_view> cell_values) {
  Init(cell_values.size());
  Row row;
  int i = 0;
  for (auto c : cell_values) {
    widths_[i] = std::max(widths_[i], c.size());
    row.emplace_back(c);
    ++i;
  }
  rows_.emplace_back(std::move(row));
}

void TextTable::PrintVia(Printer line_printer) const {
  for (const Row& row : rows_) {
    int i = 0;
    std::string line;
    for (const auto& c : row) {
      if (i > 0) line.append(separators_[i - 1]);
      const size_t fill = widths_[i] - c.size();
      switch (aligns_[i]) {
        case kLeft:
          absl::StrAppend(&line, c, std::string(fill, ' '));
          break;
        case kRight:
          absl::StrAppend(&line, std::string(fill, ' '), c);
          break;
        case kCenter:
          absl::StrAppend(&line, std::string(fill / 2, ' '), c,
                          std::string(fill - fill / 2, ' '));
          break;
      }
      ++i;
    }
    line_printer(line);
  }
}

}  // namespace silifuzz
