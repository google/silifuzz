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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_TEXT_PROTO_PRINTER_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_TEXT_PROTO_PRINTER_H_

#include <cstdint>

namespace silifuzz {

// Very basic text proto printer that does not perform dynamic memory
// allocation.
// This is purely a formatting helper, it does not perform any syntax or
// semantic validation of the arguments like field names or values.
// CHECK-fails on buffer overflow.
//
// See text_proto_printer_text.cc and text_proto_printer_integration_test.cc
// for complete usage examples.
//
// This class is thread-compatible.
class TextProtoPrinter {
 public:
  class Message;

  TextProtoPrinter() : len_(0) { buf_[0] = 0; }
  // Not copyable (no need).
  TextProtoPrinter(const TextProtoPrinter&) = delete;
  TextProtoPrinter(TextProtoPrinter&&) = default;
  TextProtoPrinter& operator=(const TextProtoPrinter&) = delete;
  TextProtoPrinter& operator=(TextProtoPrinter&&) = delete;

  // A family of methods to print various typed fields. No validation is
  // performed on the field_name or the value.
  void String(const char* field_name, const char* value);
  void Bytes(const char* field_name, const char* value, int n);
  void Enum(const char* field_name, const char* value);
  void Int(const char* field_name, int64_t value);
  void Hex(const char* field_name, uint64_t value);

  // Creates a submessage.The contents of the returned submessage appeneded to
  // the current buffer upon Message destruction.
  // Repeated calls to Message() with the same field_name will create multiple
  // output nodes.
  // The returned instance exports TextProtoPrinter API via operator->().
  // NOTE: when chaining multiple Message() calls the caller is responsible
  // for keeping all intermediate results alive for as long as at least one
  // of them is in scope or else it's a use-after-scope.
  // E.g.
  //
  //  auto m = printer.Message("foo")->Message("bar");
  //  m->Int("x", 1) /* BAD, the result of Message("foo") has been destructed */
  //
  //  printer.Message("foo")->Message("bar")->Int("x", 1)  /* GOOD */
  //
  //  or
  //
  //  auto foo = printer.Message("foo");
  //  auto bar = foo->Message("bar");
  //  bar->Int("x", 1)   /* GOOD, both foo and bar are in scope */
  Message Message(const char* field_name);

  // Returns the current contents of the print buffer.
  // To obtain the final state of buffer the caller must ensure that any
  // Message instances returned by Message() on this Printer have been
  // destructed. See Message().
  const char* c_str() const { return buf_; }

 private:
  // Maximum number of bytes a single "bytes" field value can consume in our
  // buf_. This is 4k with at most 4 bytes per char due to escaping.
  static constexpr int kMaxBytesFieldCapacity = 4096 * 4 + 1;

  // Variadic print helper.
  template <typename Arg1, typename... Args>
  void Print(Arg1& arg1, Args&&... args) {
    Print(arg1);
    Print(args...);
  }
  void Print() {}  // base case
  // Appends raw data to the output buffer.
  void Print(const char* str);
  void Print(char* str) { Print((const char*)str); }

  // Allocate space for 20 "bytes" fields plus some buffer for field names etc.
  char buf_[kMaxBytesFieldCapacity * 20 + 2048];
  int len_;
};

// A representation of a submessage in TextProtoPrinter.
// Refer to TextProtoPrinter::Message() above for creation and usage of this
// class.
class TextProtoPrinter::Message {
 public:
  // Not copyable (no need).
  Message(Message&&) = default;
  Message(const Message&) = delete;
  Message& operator=(const Message&) = delete;
  Message& operator=(Message&&) = delete;
  // Dtor. Commits the buffered content to the parent printer.
  ~Message();

  TextProtoPrinter* operator->() { return &message_printer_; }

 private:
  friend class TextProtoPrinter;
  Message(TextProtoPrinter* parent, const char* field_name);

  // The parent printer object.
  TextProtoPrinter* parent_;
  // Printer object for the current Message instance.
  TextProtoPrinter message_printer_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_TEXT_PROTO_PRINTER_H_
