// fstequal.cc

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
// Two FSTS are equal iff they their exit status is zero.
//

#include <fst/script/equal.h>

DEFINE_double(delta, fst::kDelta, "Comparison/quantization delta");

int main(int argc, char **argv) {
  namespace s = fst::script;
  using fst::script::FstClass;

  string usage = "Two FSTs are equal iff the exit status is zero.\n\n  Usage: ";
  usage += argv[0];
  usage += " in1.fst in2.fst\n";

  std::set_new_handler(FailedNewHandler);
  SET_FLAGS(usage.c_str(), &argc, &argv, true);
  if (argc != 3) {
    ShowUsage();
    return 1;
  }

  string in1_name = strcmp(argv[1], "-") == 0 ? "" : argv[1];
  string in2_name = strcmp(argv[2], "-") == 0 ? "" : argv[2];

  if (in1_name.empty() && in2_name.empty()) {
    LOG(ERROR) << argv[0] << ": Can't take both inputs from standard input.";
    return 1;
  }

  FstClass *ifst1 = FstClass::Read(in1_name);
  if (!ifst1) return 1;

  FstClass *ifst2 = FstClass::Read(in2_name);
  if (!ifst2) return 1;

  bool result = s::Equal(*ifst1, *ifst2, FLAGS_delta);
  if (!result)
    VLOG(1) << "FSTs are not equal.";

  return result ? 0 : 2;
}
