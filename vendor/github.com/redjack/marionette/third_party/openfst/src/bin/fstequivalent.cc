// fstequivalent.cc

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
// Two DFAs are equivalent iff their exit status is zero.
//

#include <fst/script/equivalent.h>
#include <fst/script/randequivalent.h>

DEFINE_double(delta, fst::kDelta, "Comparison/quantization delta");
DEFINE_bool(random, false,
            "Test equivalence by randomly selecting paths in the input FSTs");
DEFINE_int32(max_length, INT_MAX, "Maximum path length");
DEFINE_int32(npath, 1, "Number of paths to generate");
DEFINE_int32(seed, time(0), "Random seed");
DEFINE_string(select, "uniform", "Selection type: one of: "
              " \"uniform\", \"log_prob (when appropriate),"
              " \"fast_log_prob\" (when appropriate)");

int main(int argc, char **argv) {
  namespace s = fst::script;
  using fst::script::FstClass;

  string usage = "Two DFAs are equivalent iff the exit status is zero.\n\n"
      "  Usage: ";
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

  if (!FLAGS_random) {
    bool result = s::Equivalent(*ifst1, *ifst2, FLAGS_delta);
    if (!result)
      VLOG(1) << "FSTs are not equivalent.";

    return result ? 0 : 2;
  } else {
    s::RandArcSelection ras;

    if (FLAGS_select == "uniform") {
      ras = s::UNIFORM_ARC_SELECTOR;
    } else if (FLAGS_select == "log_prob") {
      ras = s::LOG_PROB_ARC_SELECTOR;
    } else if (FLAGS_select == "fast_log_prob") {
      ras = s::FAST_LOG_PROB_ARC_SELECTOR;
    } else {
      LOG(ERROR) << argv[0] << ": Unknown selection type \""
                 << FLAGS_select << "\"\n";
      return 1;
    }

    bool result = s::RandEquivalent(
        *ifst1, *ifst2,
        FLAGS_seed,
        FLAGS_npath,
        FLAGS_delta,
        fst::RandGenOptions<s::RandArcSelection>(
            ras, FLAGS_max_length));
    if (!result)
      VLOG(1) << "FSTs are not equivalent.";

    return result ? 0 : 2;
  }
}
