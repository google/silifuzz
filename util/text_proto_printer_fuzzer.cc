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

#include <string>

#include "fuzztest/fuzztest.h"
#include "absl/strings/string_view.h"
#include "google/protobuf/text_format.h"
#include "./proto/player_result.pb.h"
#include "./proto/snapshot.pb.h"
#include "./util/checks.h"
#include "./util/text_proto_printer.h"

using fuzztest::String;
using silifuzz::proto::PlayerResult;

void Bytes(const std::string& str) {
  google::protobuf::TextFormat::Parser parser;
  PlayerResult result;

  silifuzz::TextProtoPrinter printer;
  {
    auto es = printer.Message("actual_end_state");
    auto ep = es->Message("endpoint");
    es->Message("registers")->Bytes("gregs", str.data(), str.size());
  }

  CHECK(parser.ParseFromString(printer.c_str(), &result));
  CHECK_EQ(result.actual_end_state().registers().gregs(), str);
}

FUZZ_TEST(TextProtoPrinterFuzzTest, Bytes)
    .WithDomains(String().WithMaxSize(1023));
