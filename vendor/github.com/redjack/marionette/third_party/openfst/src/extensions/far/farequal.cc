// farequal.cc

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
//
// \file
// Tests if two Far files contains the same (key,fst) pairs.

#include <fst/extensions/far/main.h>
#include <fst/extensions/far/farscript.h>

DEFINE_string(begin_key, "",
              "First key to extract (def: first key in archive)");
DEFINE_string(end_key, "",
              "Last key to extract (def: last key in archive)");
DEFINE_double(delta, fst::kDelta, "Comparison/quantization delta");

int main(int argc, char **argv) {
  namespace s = fst::script;

  string usage = "Compares the FSTs in two FST archives for equality.";
  usage += "\n\n Usage:";
  usage += argv[0];
  usage += " in1.far in2.far\n";
  usage += "  Flags: begin_key end_key";

  std::set_new_handler(FailedNewHandler);
  SET_FLAGS(usage.c_str(), &argc, &argv, true);

  if (argc != 3) {
    ShowUsage();
    return 1;
  }

  string filename1(argv[1]), filename2(argv[2]);

  bool result = s::FarEqual(
      filename1, filename2, fst::LoadArcTypeFromFar(filename1),
      FLAGS_delta, FLAGS_begin_key, FLAGS_end_key);

  if (!result)
    VLOG(1) << "FARs are not equal.";

  return result ? 0 : 2;
}
