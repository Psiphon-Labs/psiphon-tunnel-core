// fstmap.cc

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
// Applies an operation to each arc of an FST.
//

#include <string>

#include <fst/script/map.h>

DEFINE_double(delta, fst::kDelta, "Comparison/quantization delta");
DEFINE_string(map_type, "identity",
              "Map operation, one of: \"arc_sum\", \"identity\", \"invert\", "
              "\"plus (--weight)\", \"quantize (--delta)\", \"rmweight\", "
              "\"superfinal\", \"times (--weight)\", \"to_log\", \"to_log64\", "
              "\"to_standard\"");
DEFINE_string(weight, "", "Weight parameter");

int main(int argc, char **argv) {
  namespace s = fst::script;
  using fst::script::FstClass;
  using fst::script::MutableFstClass;
  using fst::script::VectorFstClass;

  string usage = "Applies an operation to each arc of an FST.\n\n  Usage: ";
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

  s::WeightClass w = !FLAGS_weight.empty() ?
      s::WeightClass(ifst->WeightType(), FLAGS_weight) :
      (FLAGS_map_type == "times" ?
       s::WeightClass::One() : s::WeightClass::Zero());

  s::MapType mt;
  if (FLAGS_map_type == "arc_sum") {
    mt = s::ARC_SUM_MAPPER;
  } else if (FLAGS_map_type == "identity") {
    mt = s::IDENTITY_MAPPER;
  } else if (FLAGS_map_type == "invert") {
    mt = s::INVERT_MAPPER;
  } else if (FLAGS_map_type == "plus") {
    mt = s::PLUS_MAPPER;
  } else if (FLAGS_map_type == "quantize") {
    mt = s::QUANTIZE_MAPPER;
  } else if (FLAGS_map_type == "rmweight") {
    mt = s::RMWEIGHT_MAPPER;
  } else if (FLAGS_map_type == "superfinal") {
    mt = s::SUPERFINAL_MAPPER;
  } else if (FLAGS_map_type == "times") {
    mt = s::TIMES_MAPPER;
  } else if (FLAGS_map_type == "to_log") {
    mt = s::TO_LOG_MAPPER;
  } else if (FLAGS_map_type == "to_log64") {
    mt = s::TO_LOG64_MAPPER;
  } else if (FLAGS_map_type == "to_standard") {
    mt = s::TO_STD_MAPPER;
  } else {
    LOG(ERROR) << argv[0] << ": Unknown map type \""
               << FLAGS_map_type << "\"\n";
    return 1;
  }

  FstClass *ofst = s::Map(*ifst, mt, FLAGS_delta, w);

  ofst->Write(out_name);

  return 0;
}
