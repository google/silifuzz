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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_LINE_PRINTER_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_LINE_PRINTER_H_

#include <functional>
#include <string>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"

namespace silifuzz {

// A helper class to output indented lines of text.
//
// This class is thread-compatible.
class LinePrinter {
 public:
  static constexpr int kDefaultIndentStep = 2;

  // The line printing/output function.
  using Printer = std::function<void(absl::string_view text_line)>;

  // Some common values for a `Printer`.
  static void StdOutPrinter(absl::string_view text_line);
  static void StdErrPrinter(absl::string_view text_line);
  static void LogInfoPrinter(absl::string_view text_line);
  static void LogErrorPrinter(absl::string_view text_line);
  static Printer StringPrinter(std::string* dest);

  // *this will print via line_printer.
  explicit LinePrinter(const Printer& line_printer, int initial_indent = 0);

  // Not copyable or movable (no need).
  LinePrinter(const LinePrinter&) = delete;
  LinePrinter& operator=(const LinePrinter&) = delete;

  // Returns *this as a line-printing `Printer` function.
  Printer AsPrinter();

  // Print a line of text while adding indentation and newline.
  void Line(absl::string_view text);

  // Convenient StrCat-eliminating overload.
  template <typename... Ts>
  void Line(Ts&&... args) {
    Line(absl::string_view(absl::StrCat(std::forward<Ts>(args)...)));
  }

  // Increase indentaion of the printed lines.
  void Indent(int indent = kDefaultIndentStep);

  // Decrease indentaion of the printed lines.
  void Unindent(int indent = kDefaultIndentStep);

  // Current indentation.
  int indent() const { return indent_str_.size(); }

 private:
  // Destination.
  const Printer line_printer_;

  // Current indentation.
  std::string indent_str_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_LINE_PRINTER_H_
