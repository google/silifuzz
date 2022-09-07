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

#include "./util/line_printer.h"

#include <cstdio>

#include "./util/checks.h"

namespace silifuzz {

// static
void LinePrinter::StdOutPrinter(absl::string_view text_line) {
  int size = text_line.size();
  printf("%*.*s\n", size, size, text_line.data());
}

// static
void LinePrinter::StdErrPrinter(absl::string_view text_line) {
  int size = text_line.size();
  fprintf(stderr, "%*.*s\n", size, size, text_line.data());
}

// static
void LinePrinter::LogInfoPrinter(absl::string_view text_line) {
  LOG_INFO(text_line);
}

// static
void LinePrinter::LogErrorPrinter(absl::string_view text_line) {
  LOG_ERROR(text_line);
}

// static
LinePrinter::Printer LinePrinter::StringPrinter(std::string* dest) {
  return [dest](absl::string_view text_line) {
    dest->append(text_line);
    dest->append("\n");
  };
}

// ----------------------------------------------------------------------- //

LinePrinter::LinePrinter(const Printer& line_printer, int initial_indent)
    : line_printer_(line_printer),
      indent_str_(DCHECK_AND_USE(initial_indent >= 0, initial_indent), ' ') {}

LinePrinter::Printer LinePrinter::AsPrinter() {
  return [this](absl::string_view text_line) { Line(text_line); };
}

void LinePrinter::Line(absl::string_view text) {
  line_printer_(absl::StrCat(indent_str_, text));
}

void LinePrinter::Indent(int indent) {
  DCHECK_GE(indent, 0);
  indent_str_.append(std::string(indent, ' '));
}

void LinePrinter::Unindent(int indent) {
  DCHECK_GE(indent, 0);
  DCHECK_GE(indent_str_.size(), indent);
  indent_str_.resize(indent_str_.size() - indent);
}

}  // namespace silifuzz
