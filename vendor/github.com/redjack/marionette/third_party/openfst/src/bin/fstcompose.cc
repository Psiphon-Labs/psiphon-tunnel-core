// fstcompose.cc

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Copyright 2005-2010 Google, Inc.
// Author: riley@google.com (Michael Riley)
// Modified: jpr@google.com (Jake Ratkiewicz) to use FstClass
//
// \file
// Composes two FSTs.
//

#include <fst/script/compose.h>
#include <fst/script/connect.h>


DEFINE_string(compose_filter, "auto",
              "Composition filter, one of: \"alt_sequence\", \"auto\", "
              "\"match\", \"null\", \"sequence\"");
DEFINE_bool(connect, true, "Trim output");


int main(int argc, char **argv) {
  namespace s = fst::script;
  using fst::script::FstClass;
  using fst::script::MutableFstClass;
  using fst::script::VectorFstClass;

  string usage = "Composes two FSTs.\n\n  Usage: ";
  usage += argv[0];
  usage += " in1.fst in2.fst [out.fst]\n";

  std::set_new_handler(FailedNewHandler);
  SET_FLAGS(usage.c_str(), &argc, &argv, true);
  if (argc < 3 || argc > 4) {
    ShowUsage();
    return 1;
  }

  string in1_name = strcmp(argv[1], "-") != 0 ? argv[1] : "";
  string in2_name = (argc > 2 && (strcmp(argv[2], "-") != 0)) ? argv[2] : "";
  string out_name = argc > 3 ? argv[3] : "";

  if (in1_name.empty() && in2_name.empty()) {
    LOG(ERROR) << argv[0] << ": Can't take both inputs from standard input.";
    return 1;
  }

  FstClass *ifst1 = FstClass::Read(in1_name);
  if (!ifst1) return 1;

  FstClass *ifst2 = FstClass::Read(in2_name);
  if (!ifst2) return 1;

  if (ifst1->ArcType() != ifst2->ArcType()) {
    LOG(ERROR) << argv[0] << ": Input FSTs must have the same arc type.";
    return 1;
  }

  VectorFstClass ofst(ifst1->ArcType());

  fst::ComposeFilter compose_filter;

  if (FLAGS_compose_filter == "alt_sequence") {
    compose_filter = fst::ALT_SEQUENCE_FILTER;
  } else if (FLAGS_compose_filter == "auto") {
    compose_filter = fst::AUTO_FILTER;
  } else if (FLAGS_compose_filter == "match") {
    compose_filter = fst::MATCH_FILTER;
  } else if (FLAGS_compose_filter == "null") {
    compose_filter = fst::NULL_FILTER;
  } else if (FLAGS_compose_filter == "sequence") {
    compose_filter = fst::SEQUENCE_FILTER;
  } else {
    LOG(ERROR) << argv[0] << "Unknown compose filter type: "
               << FLAGS_compose_filter;
    return 1;
  }

  fst::ComposeOptions opts(FLAGS_connect, compose_filter);

  s::Compose(*ifst1, *ifst2, &ofst, opts);

  ofst.Write(out_name);

  return 0;
}
