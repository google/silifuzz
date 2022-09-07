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

#include "./util/text_proto_printer.h"

#include <cstdint>
#include <cstring>

#include "./util/checks.h"
#include "./util/itoa.h"

namespace silifuzz {

void TextProtoPrinter::String(const char* field_name, const char* value) {
  Bytes(field_name, value, strlen(value));
}

// Borrowed from absl/strings/escaping.cc
/* clang-format off */
constexpr char kEscapedLen[256] = {
    4, 4, 4, 4, 4, 4, 4, 4, 4, 2, 2, 4, 4, 2, 4, 4,  // \t, \n, \r
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    1, 1, 2, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1,  // ", '
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // '0'..'9'
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // 'A'..'O'
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1,  // 'P'..'Z', '\'
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // 'a'..'o'
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 4,  // 'p'..'z', DEL
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
};
/* clang-format on */
void TextProtoPrinter::Bytes(const char* field_name, const char* value, int n) {
  if (n > kMaxBytesFieldCapacity) {
    LOG_FATAL("TextProtoPrinter::Bytes buffer too small");
  }
  char buf[kMaxBytesFieldCapacity];
  char* ptr = buf;
  for (int i = 0; i < n; ++i) {
    unsigned char c = value[i];
    int char_len = kEscapedLen[c];
    if (char_len == 1) {
      *ptr++ = c;
    } else if (char_len == 2) {
      switch (c) {
        case '\n':
          *ptr++ = '\\';
          *ptr++ = 'n';
          break;
        case '\r':
          *ptr++ = '\\';
          *ptr++ = 'r';
          break;
        case '\t':
          *ptr++ = '\\';
          *ptr++ = 't';
          break;
        case '\"':
          *ptr++ = '\\';
          *ptr++ = '"';
          break;
        case '\'':
          *ptr++ = '\\';
          *ptr++ = '\'';
          break;
        case '\\':
          *ptr++ = '\\';
          *ptr++ = '\\';
          break;
      }
    } else {
      constexpr char kHexDigits[] = "0123456789abcdef";
      *ptr++ = '\\';
      *ptr++ = 'x';
      *ptr++ = kHexDigits[((c & 0xF0) >> 4)];
      *ptr++ = kHexDigits[(c & 0xF)];
    }
  }
  *ptr = '\0';
  Print(field_name, ":'", buf, "' ");
}

void TextProtoPrinter::Enum(const char* field_name, const char* value) {
  Print(field_name, ":", value, " ");
}

void TextProtoPrinter::Int(const char* field_name, int64_t value) {
  Print(field_name, ":", IntStr(value), " ");
}

void TextProtoPrinter::Hex(const char* field_name, uint64_t value) {
  Print(field_name, ":", HexStr(value), " ");
}

class TextProtoPrinter::Message TextProtoPrinter::Message(
    const char* field_name) {
  return {this, field_name};
}

void TextProtoPrinter::Print(const char* str) {
  int n = strlen(str) + 1;  // +1 to grab the terminating \0.
  if (n + len_ >= sizeof(buf_)) {
    LOG_FATAL("TextProtoPrinter::buf_ too small");
  }
  memcpy(buf_ + len_, str, n);
  len_ += n - 1;
}

TextProtoPrinter::Message::Message(TextProtoPrinter* parent,
                                   const char* field_name)
    : parent_(parent), message_printer_() {
  message_printer_.Print(field_name, ":{ ");
}

TextProtoPrinter::Message::~Message() {
  parent_->Print(message_printer_.c_str());
  parent_->Print("} ");
}

}  // namespace silifuzz
