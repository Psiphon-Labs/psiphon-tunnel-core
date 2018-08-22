// farprintstrings.cc

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
// Output as strings the string FSTs in a finite-state archive.
//

#include <fst/extensions/far/farscript.h>

DEFINE_string(filename_prefix, "", "Prefix to append to filenames");
DEFINE_string(filename_suffix, "", "Suffix to append to filenames");
DEFINE_int32(generate_filenames, 0,
             "Generate N digit numeric filenames (def: use keys)");
DEFINE_string(begin_key, "",
              "First key to extract (def: first key in archive)");
DEFINE_string(end_key, "",
              "Last key to extract (def: last key in archive)");
// PrintStringsMain specific flag definitions.
DEFINE_bool(print_key, false, "Prefix each string by its key");
DEFINE_bool(print_weight, false, "Suffix each string by its weight");
DEFINE_string(entry_type, "line", "Entry type: one of : "
              "\"file\" (one FST per file), \"line\" (one FST per line)");
DEFINE_string(token_type, "symbol", "Token type: one of : "
              "\"symbol\", \"byte\", \"utf8\"");
DEFINE_string(symbols, "", "Label symbol table");
DEFINE_bool(initial_symbols, true,
            "Uses symbol table from the first Fst in archive for all entries.");


int  main(int argc, char **argv) {
  namespace s = fst::script;

  string usage = "Print as string the string FSTs in an archive.\n\n Usage:";
  usage += argv[0];
  usage += " [in1.far in2.far ...]\n";

  std::set_new_handler(FailedNewHandler);
  SET_FLAGS(usage.c_str(), &argc, &argv, true);

  vector<string> ifilenames;
  for (int i = 1; i < argc; ++i)
    ifilenames.push_back(strcmp(argv[i], "") != 0 ? argv[i] : "");
  if (ifilenames.empty()) ifilenames.push_back("");

  string arc_type = fst::LoadArcTypeFromFar(ifilenames[0]);

  s::FarPrintStrings(ifilenames, arc_type,
                     fst::StringToFarEntryType(FLAGS_entry_type),
                     fst::StringToFarTokenType(FLAGS_token_type),
                     FLAGS_begin_key, FLAGS_end_key,
                     FLAGS_print_key, FLAGS_print_weight,
                     FLAGS_symbols, FLAGS_initial_symbols,
                     FLAGS_generate_filenames,
                     FLAGS_filename_prefix, FLAGS_filename_suffix);

  return 0;
}
