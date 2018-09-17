// fstreverse.cc

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
// Modified: jpr@google.com (Jake Ratkiewicz) Changed to use FstClass
//
// \file
// Reverses the paths in an FST.
//

#include <string>

#include <fst/script/reverse.h>
#include <fst/script/fst-class.h>
#include <iostream>
#include <fstream>
#include <sstream>

DEFINE_bool(require_superinitial, true, "Always create a superinitial state");

int main(int argc, char **argv) {
  using fst::script::FstClass;
  using fst::script::VectorFstClass;
  using fst::script::Reverse;

  string usage = "Reverses the paths in an FST.\n\n  Usage: ";
  usage += argv[0];
  usage += " [in.fst [out.fst]]\n";

  std::set_new_handler(FailedNewHandler);
  SET_FLAGS(usage.c_str(), &argc, &argv, true);
  if (argc > 3) {
    ShowUsage();
    return 1;
  }

  string in_name = (argc > 1 && (strcmp(argv[1], "-") != 0)) ? argv[1] : "";
  string out_name = argc > 2 ? argv[2] : "";

  FstClass *ifst = FstClass::Read(in_name);
  if (!ifst) return 1;

  VectorFstClass *out = new VectorFstClass(ifst->ArcType());

  Reverse(*ifst, out, FLAGS_require_superinitial);

  out->Write(out_name);

  return 0;
}
