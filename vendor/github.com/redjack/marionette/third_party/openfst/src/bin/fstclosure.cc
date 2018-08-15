// fstclosure.cc

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
// Creates the Kleene closure of an FST.
//

#include <fst/script/closure.h>

DEFINE_bool(closure_plus, false,
            "Do not add the empty path (T+ instead of T*)");

int main(int argc, char **argv) {
  using fst::script::FstClass;
  using fst::script::MutableFstClass;

  string usage = "Creates the Kleene closure of an FST.\n\n  Usage: ";
  usage += argv[0];
  usage += " [in.fst [out.fst]]\n";

  std::set_new_handler(FailedNewHandler);
  SET_FLAGS(usage.c_str(), &argc, &argv, true);
  if (argc > 3) {
    ShowUsage();
    return 1;
  }

  string in_fname = (argc > 1 && strcmp(argv[1], "-") != 0) ? argv[1] : "";
  string out_fname = argc > 2 ? argv[2] : "";

  MutableFstClass *fst = MutableFstClass::Read(in_fname, true);
  if (!fst) return 1;

  fst::ClosureType closure_type =
      FLAGS_closure_plus ? fst::CLOSURE_PLUS : fst::CLOSURE_STAR;

  fst::script::Closure(fst, closure_type);
  fst->Write(out_fname);

  return 0;
}
