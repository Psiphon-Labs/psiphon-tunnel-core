// fstarcsort.cc

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
// Sorts arcs of an FST.
//

#include <string>

#include <fst/compat.h>
#include <fst/script/arcsort.h>

DEFINE_string(sort_type, "ilabel",
              "Comparison method, one of: \"ilabel\", \"olabel\"");

int main(int argc, char **argv) {
  using fst::script::FstClass;
  using fst::script::MutableFstClass;
  using fst::script::ArcSort;

  string usage = "Sorts arcs of an FST.\n\n  Usage: ";
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

  MutableFstClass *fst = MutableFstClass::Read(in_name, true);
  if (!fst) return 1;

  if (FLAGS_sort_type == "ilabel") {
    ArcSort(fst, fst::script::ILABEL_COMPARE);
  } else if (FLAGS_sort_type == "olabel") {
    ArcSort(fst, fst::script::OLABEL_COMPARE);
  } else {
    LOG(ERROR) << argv[0] << ": Unknown sort type \""
               << FLAGS_sort_type << "\"\n";
    return 1;
  }

  fst->Write(out_name);

  return 0;
}
