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

#include <cstring>

#include "./util/checks.h"
#include "./util/nolibc_gunit.h"

namespace silifuzz {
namespace {

TEST(TextProtoPrinter, TestBasic) {
  {
    TextProtoPrinter p;
    EXPECT_STR_EQ(p.c_str(), "");
  }
  {
    TextProtoPrinter p;
    p.Bytes("v", "\x00'\xff", 3);
    EXPECT_STR_EQ(p.c_str(), "v:'\\x00\\'\\xff' ");
  }

  {
    TextProtoPrinter p;
    { auto m = p.Message("foo"); }
    EXPECT_STR_EQ(p.c_str(), "foo:{ } ");
  }
  {
    TextProtoPrinter p;
    p.Int("int", 0);
    p.Int("int", -1);
    p.String("str", "str");
    p.String("str", "");
    p.Enum("enum", "ENUM_VAL");
    p.Hex("hex", 0x100);
    EXPECT_STR_EQ(p.c_str(),
                  "int:0 int:-1 str:'str' str:'' enum:ENUM_VAL hex:0x100 ");
  }
}

TEST(TextProtoPrinter, Nesting) {
  TextProtoPrinter p;
  {
    p.Message("foo")->Message("bar")->Message("quux")->String("nested", "1");
    p.Message("foo")->String("foo_nested", "1");
  }
  // There is no AST so multiple invocations of p.Message("foo") will create
  // repeated nodes.
  EXPECT_STR_EQ(p.c_str(),
                "foo:{ bar:{ quux:{ nested:'1' } } } foo:{ foo_nested:'1' } ");
}

TEST(TextProtoPrinter, Interleaving) {
  TextProtoPrinter p;
  {
    auto foo = p.Message("foo");
    auto bar = p.Message("bar");
    foo->Int("foo_int", 1);
    p.Int("root_int", 0);
    bar->Int("bar_int", 3);
    foo->Int("foo_int", 2);
  }
  EXPECT_STR_EQ(p.c_str(),
                "root_int:0 bar:{ bar_int:3 } foo:{ foo_int:1 foo_int:2 } ");
}

TEST(TextProtoPrinter, Overflow) {
  TextProtoPrinter p;
  ABSL_ATTRIBUTE_UNUSED auto overflow = [&] {
    for (int i = 0; i < 100000; ++i) {
      p.Int("bogus", 1);
    }
  };
  EXPECT_DEATH_IF_SUPPORTED(overflow(), "TextProtoPrinter::buf_ too small");
}

}  // namespace
}  // namespace silifuzz

NOLIBC_TEST_MAIN({
  RUN_TEST(TextProtoPrinter, TestBasic);
  RUN_TEST(TextProtoPrinter, Nesting);
  RUN_TEST(TextProtoPrinter, Interleaving);
  RUN_TEST(TextProtoPrinter, Overflow);
})
