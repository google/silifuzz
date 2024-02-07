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

#include "google/protobuf/duration.pb.h"
#include "gtest/gtest.h"
#include "google/protobuf/text_format.h"
#include "./proto/player_result.pb.h"
#include "./proto/snapshot.pb.h"
#include "./util/text_proto_printer.h"

namespace silifuzz {
namespace {

TEST(TextProtoPrinter, IntegrationTest) {
  google::protobuf::TextFormat::Parser parser;
  proto::PlayerResult result;

  TextProtoPrinter printer;
  printer.Enum("outcome", "REGISTER_STATE_MISMATCH");
  printer.Int("end_state_index", 1);
  printer.Int("cpu_id", 100);
  char byte_val[] =
      "\x00"
      "c"
      "\n"
      "\r"
      "\t"
      "\\"
      "\""
      "\'"
      "\x7f"
      ":abcABC09:"
      "\x80"
      "\xff";
  {
    auto cpu_usage = printer.Message("cpu_usage");
    cpu_usage->Int("nanos", 9999);
    auto es = printer.Message("actual_end_state");
    auto ep = es->Message("endpoint");
    ep->Hex("instruction_address", 0xFFFF);
    es->Message("registers")->Bytes("gregs", byte_val, sizeof(byte_val));
  }

  ASSERT_TRUE(parser.ParseFromString(printer.c_str(), &result));
  EXPECT_EQ(result.outcome(), proto::PlayerResult::REGISTER_STATE_MISMATCH);
  EXPECT_EQ(result.end_state_index(), 1);
  EXPECT_EQ(result.cpu_id(), 100);
  EXPECT_EQ(result.cpu_usage().nanos(), 9999);
  EXPECT_EQ(result.cpu_usage().seconds(), 0);
  EXPECT_EQ(result.actual_end_state().endpoint().instruction_address(), 0xFFFF);
  EXPECT_EQ(result.actual_end_state().registers().gregs(),
            std::string(byte_val, sizeof(byte_val)));

  proto::Snapshot snapshot;
  TextProtoPrinter snapshot_printer;
  snapshot_printer.String("id", "\'\"012345abcd");
  ASSERT_TRUE(parser.ParseFromString(snapshot_printer.c_str(), &snapshot));
  EXPECT_EQ(snapshot.id(), "\'\"012345abcd");
}

}  // namespace
}  // namespace silifuzz
