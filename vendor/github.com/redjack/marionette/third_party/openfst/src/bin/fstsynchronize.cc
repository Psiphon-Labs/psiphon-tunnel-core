// fstsynchronize.cc

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
// Author: allauzen@google.com (Cyril Allauzen)
// Modified: jpr@google.com (Jake Ratkiewicz) to use FstClass
//
// \file
// Synchronizes an FST.
//

#include <fst/script/synchronize.h>

int main(int argc, char **argv) {
  namespace s = fst::script;
  using fst::script::FstClass;
  using fst::script::VectorFstClass;

  string usage = "Synchronizes an FST.\n\n  Usage: ";
  usage += argv[0];
  usage += " [in.fst [out.fst]]\n";

  std::set_new_handler(FailedNewHandler);
  SET_FLAGS(usage.c_str(), &argc, &argv, true);
  if (argc > 3) {
    ShowUsage();
    return 1;
  }

  string in_name = (argc > 1 && strcmp(argv[1], "-") != 0) ? argv[1] : "";
  string out_name = argc > 2 ? argv[2] : "";

  FstClass *ifst = FstClass::Read(in_name);
  if (!ifst) return 1;

  VectorFstClass ofst(ifst->ArcType());

  s::Synchronize(*ifst, &ofst);

  ofst.Write(out_name);

  return 0;
}
