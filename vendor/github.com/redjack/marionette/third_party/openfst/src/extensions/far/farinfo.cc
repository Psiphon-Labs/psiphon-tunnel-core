// farinfo.cc

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
// Modified: jpr@google.com (Jake Ratkiewicz) to use new arc dispatching
//
// \file
// Prints some basic information about the FSTs in an FST archive.
//

#include <fst/extensions/far/main.h>
#include <fst/extensions/far/farscript.h>

DEFINE_string(begin_key, "",
              "First key to extract (def: first key in archive)");
DEFINE_string(end_key, "",
              "Last key to extract (def: last key in archive)");

DEFINE_bool(list_fsts, false, "Display FST information for each key");

int main(int argc, char **argv) {
  namespace s = fst::script;

  string usage = "Prints some basic information about the FSTs in an FST ";
  usage += "archive.\n\n Usage:";
  usage += argv[0];
  usage += " [in1.far in2.far...]\n";
  usage += "  Flags: begin_key end_key list_fsts";

  std::set_new_handler(FailedNewHandler);
  SET_FLAGS(usage.c_str(), &argc, &argv, true);

  vector<string> filenames;
  for (int i = 1; i < argc; ++i)
    filenames.push_back(strcmp(argv[i], "") != 0 ? argv[i] : "");
  if (filenames.empty())
    filenames.push_back("");

  s::FarInfo(filenames, fst::LoadArcTypeFromFar(filenames[0]),
             FLAGS_begin_key, FLAGS_end_key, FLAGS_list_fsts);
}
