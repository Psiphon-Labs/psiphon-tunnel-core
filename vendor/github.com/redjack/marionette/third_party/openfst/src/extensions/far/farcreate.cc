// farcreate.cc

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
// Modified: jpr@google.com (Jake Ratkiewicz) to use new dispatch
//
// \file
// Creates a finite-state archive from input FSTs.
//

#include <fst/extensions/far/farscript.h>
#include <fst/extensions/far/main.h>
#include <fst/extensions/far/far.h>

DEFINE_string(key_prefix, "", "Prefix to append to keys");
DEFINE_string(key_suffix, "", "Suffix to append to keys");
DEFINE_int32(generate_keys, 0,
             "Generate N digit numeric keys (def: use file basenames)");
DEFINE_string(far_type, "default",
              "FAR file format type: one of: \"default\", "
              "\"stlist\", \"sttable\"");
DEFINE_bool(file_list_input, false,
            "Each input files contains a list of files to be processed");

int main(int argc, char **argv) {
  namespace s = fst::script;

  string usage = "Creates a finite-state archive from input FSTs.\n\n Usage:";
  usage += argv[0];
  usage += " [in1.fst [[in2.fst ...] out.far]]\n";

  std::set_new_handler(FailedNewHandler);
  SET_FLAGS(usage.c_str(), &argc, &argv, true);

  vector<string> in_fnames;
  for (unsigned i = 1; i < argc - 1; ++i)
    in_fnames.push_back(strcmp(argv[i], "") != 0 ? argv[i] : "");
  if (in_fnames.empty())
    in_fnames.push_back(argc == 2 && strcmp(argv[1], "-") != 0 ? argv[1] : "");

  string out_fname =
      argc > 2 && strcmp(argv[argc - 1], "-") != 0 ? argv[argc - 1] : "";

  string arc_type = fst::LoadArcTypeFromFst(in_fnames[0]);
  fst::FarType far_type = fst::FarTypeFromString(FLAGS_far_type);

  s::FarCreate(in_fnames, out_fname, arc_type, FLAGS_generate_keys,
               FLAGS_file_list_input, far_type, FLAGS_key_prefix,
               FLAGS_key_suffix);
}
