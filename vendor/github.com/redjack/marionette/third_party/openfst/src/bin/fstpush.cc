// fstpush.cc

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
// \file
// Pushes weights and/or output labels in an FST toward the initial or
// final states.

#include <fst/script/push.h>

DEFINE_double(delta, fst::kDelta, "Comparison/quantization delta");
DEFINE_bool(push_weights, false, "Push weights");
DEFINE_bool(push_labels, false, "Push output labels");
DEFINE_bool(remove_total_weight, false,
            "Remove total weight when pushing weights");
DEFINE_bool(remove_common_affix, false,
            "Remove common prefix/suffix when pushing labels");
DEFINE_bool(to_final, false, "Push/reweight to final (vs. to initial) states");


int main(int argc, char **argv) {
  namespace s = fst::script;
  using fst::script::FstClass;
  using fst::script::VectorFstClass;

  string usage = "Pushes weights and/or olabels in an FST.\n\n  Usage: ";
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

  uint32 flags = 0;
  if (FLAGS_push_weights)
    flags |= fst::kPushWeights;
  if (FLAGS_push_labels)
    flags |= fst::kPushLabels;
  if (FLAGS_remove_total_weight)
    flags |= fst::kPushRemoveTotalWeight;
  if (FLAGS_remove_common_affix)
    flags |= fst::kPushRemoveCommonAffix;

  VectorFstClass ofst(ifst->ArcType());

  if (FLAGS_to_final) {
    s::Push(*ifst, &ofst, flags, fst::REWEIGHT_TO_FINAL, FLAGS_delta);
  } else {
    s::Push(*ifst, &ofst, flags, fst::REWEIGHT_TO_INITIAL, FLAGS_delta);
  }

  ofst.Write(out_name);

  return 0;
}
