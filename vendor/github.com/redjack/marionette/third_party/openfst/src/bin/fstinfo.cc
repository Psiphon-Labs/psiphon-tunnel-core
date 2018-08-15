// fstinfo.cc

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
// Prints out various information about an FST such as number of states
// and arcs and property values (see properties.h).
//

#include <fst/script/info.h>

DEFINE_string(arc_filter, "any", "Arc filter: one of :"
              " \"any\", \"epsilon\", \"iepsilon\", \"oepsilon\"");
DEFINE_string(info_type, "auto",
              "Info format: one of: \"auto\", \"long\", \"short\"");
DEFINE_bool(pipe, false, "Send info to stderr, input to stdout");
DEFINE_bool(test_properties, true,
            "Compute property values (if unknown to FST)");
DEFINE_bool(fst_verify, true, "Verify FST sanity");

int main(int argc, char **argv) {
  namespace s = fst::script;
  using fst::script::FstClass;

  string usage = "Prints out information about an FST.\n\n  Usage: ";
  usage += argv[0];
  usage += " [in.fst]\n";

  std::set_new_handler(FailedNewHandler);
  SET_FLAGS(usage.c_str(), &argc, &argv, true);
  if (argc > 2) {
    ShowUsage();
    return 1;
  }

  string in_name = (argc > 1 && (strcmp(argv[1], "-") != 0)) ? argv[1] : "";

  FstClass *ifst = FstClass::Read(in_name);
  if (!ifst) return 1;

  s::PrintFstInfo(*ifst, FLAGS_test_properties, FLAGS_arc_filter,
                  FLAGS_info_type, FLAGS_fst_verify, FLAGS_pipe);

  return 0;
}
