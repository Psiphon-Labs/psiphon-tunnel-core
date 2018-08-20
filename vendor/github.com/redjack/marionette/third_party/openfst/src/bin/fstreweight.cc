// fstreweight.cc

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
// Reweights an FST.
//

#include <fst/script/reweight.h>
#include <fst/script/text-io.h>

DEFINE_bool(to_final, false, "Push/reweight to final (vs. to initial) states");

int main(int argc, char **argv) {
  namespace s = fst::script;
  using fst::script::FstClass;
  using fst::script::MutableFstClass;

  string usage = "Reweights an FST.\n\n  Usage: ";
  usage += argv[0];
  usage += " in.fst potential.txt [out.fst]\n";

  std::set_new_handler(FailedNewHandler);
  SET_FLAGS(usage.c_str(), &argc, &argv, true);
  if (argc < 3 || argc > 4) {
    ShowUsage();
    return 1;
  }

  string in_fname = argv[1];
  string potentials_fname = argv[2];
  string out_fname = argc > 3 ? argv[3] : "";

  MutableFstClass *fst = MutableFstClass::Read(in_fname, true);
  if (!fst) return 1;

  vector<s::WeightClass> potential;
  if (!s::ReadPotentials(fst->WeightType(), potentials_fname, &potential))
    return 1;

  fst::ReweightType reweight_type = FLAGS_to_final ?
      fst::REWEIGHT_TO_FINAL :
      fst::REWEIGHT_TO_INITIAL;

  s::Reweight(fst, potential, reweight_type);
  fst->Write(out_fname);

  return 0;
}
