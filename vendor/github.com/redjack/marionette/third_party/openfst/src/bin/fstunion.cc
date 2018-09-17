// fstunion.cc

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
// Modified: jpr@google.com (Jake Ratkiewicz) - to use FstClass
//
// \file
// Creates the union of two FSTs.
//

#include <string>

#include <fst/script/union.h>
#include <iostream>
#include <fstream>
#include <sstream>

int main(int argc, char **argv) {
  using fst::script::FstClass;
  using fst::script::MutableFstClass;
  using fst::script::Union;

  string usage = "Creates the union of two FSTs.\n\n  Usage: ";
  usage += argv[0];
  usage += " in1.fst in2.fst [out.fst]\n";

  std::set_new_handler(FailedNewHandler);
  SET_FLAGS(usage.c_str(), &argc, &argv, true);
  if (argc < 3 || argc > 4) {
    ShowUsage();
    return 1;
  }

  string in1_name = strcmp(argv[1], "-") != 0 ? argv[1] : "";
  string in2_name = strcmp(argv[2], "-") != 0 ? argv[2] : "";
  string out_name = argc > 3 ? argv[3] : "";

  if (in1_name == "" && in2_name == "") {
    LOG(ERROR) << argv[0]
               << ": Can't use standard i/o for both inputs.";
    return 1;
  }

  MutableFstClass *fst1 = MutableFstClass::Read(in1_name, true);
  if (!fst1) return 1;

  FstClass *fst2 = FstClass::Read(in2_name);
  if (!fst2) {
    return 1;
  }

  Union(fst1, *fst2);
  fst1->Write(out_name);

  return 0;
}
