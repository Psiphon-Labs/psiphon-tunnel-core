// fstintersect.cc

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
// Intersects two FSTs.
//

#include <fst/script/intersect.h>
#include <fst/script/connect.h>

DEFINE_string(compose_filter, "auto",
              "Composition filter, one of: \"alt_sequence\", \"auto\", "
              "\"match\", \"sequence\"");
DEFINE_bool(connect, true, "Trim output");

int main(int argc, char **argv) {
  namespace s = fst::script;
  using fst::script::FstClass;
  using fst::script::VectorFstClass;


  string usage = "Intersects two FSAs.\n\n  Usage: ";
  usage += argv[0];
  usage += " in1.fst in2.fst [out.fst]\n";
  usage += "  Flags: connect\n";

  std::set_new_handler(FailedNewHandler);
  SET_FLAGS(usage.c_str(), &argc, &argv, true);
  if (argc < 3 || argc > 4) {
    ShowUsage();
    return 1;
  }

  string in1_name = strcmp(argv[1], "-") == 0 ? "" : argv[1];
  string in2_name = strcmp(argv[2], "-") == 0 ? "" : argv[2];
  string out_name = argc > 3 ? argv[3] : "";

  if (in1_name.empty() && in2_name.empty()) {
    LOG(ERROR) << argv[0] << ": Can't take both inputs from standard input.";
    return 1;
  }

  FstClass *ifst1 = FstClass::Read(in1_name);
  if (!ifst1) return 1;
  FstClass *ifst2 = FstClass::Read(in2_name);
  if (!ifst2) return 1;

  VectorFstClass ofst(ifst1->ArcType());

  fst::ComposeFilter compose_filter;

  if (FLAGS_compose_filter == "alt_sequence") {
    compose_filter = fst::ALT_SEQUENCE_FILTER;
  } else if (FLAGS_compose_filter == "auto") {
    compose_filter = fst::AUTO_FILTER;
  } else if (FLAGS_compose_filter == "match") {
    compose_filter = fst::MATCH_FILTER;
  } else if (FLAGS_compose_filter == "sequence") {
    compose_filter = fst::SEQUENCE_FILTER;
  } else {
    LOG(ERROR) << argv[0] << "Unknown compose filter type: "
               << FLAGS_compose_filter;
    return 1;
  }

  fst::IntersectOptions opts(FLAGS_connect, compose_filter);

  s::Intersect(*ifst1, *ifst2, &ofst, opts);

  ofst.Write(out_name);

  return 0;
}
