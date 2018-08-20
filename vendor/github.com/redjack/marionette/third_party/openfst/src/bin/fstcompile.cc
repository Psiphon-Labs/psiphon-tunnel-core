// fstcompile.cc

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
// Creates binary FSTs from simple text format used by AT&T
// (see http://www.research.att.com/projects/mohri/fsm/doc4/fsm.5.html).

#include <fst/script/compile.h>

DEFINE_bool(acceptor, false, "Input in acceptor format");
DEFINE_string(arc_type, "standard", "Output arc type");
DEFINE_string(fst_type, "vector", "Output FST type");
DEFINE_string(isymbols, "", "Input label symbol table");
DEFINE_string(osymbols, "", "Output label symbol table");
DEFINE_string(ssymbols, "", "State label symbol table");
DEFINE_bool(keep_isymbols, false, "Store input label symbol table with FST");
DEFINE_bool(keep_osymbols, false, "Store output label symbol table with FST");
DEFINE_bool(keep_state_numbering, false, "Do not renumber input states");
DEFINE_bool(allow_negative_labels, false,
            "Allow negative labels (not recommended; may cause conflicts)");

int main(int argc, char **argv) {
  namespace s = fst::script;
  using fst::istream;
  using fst::ifstream;
  using fst::SymbolTable;

  string usage = "Creates binary FSTs from simple text format.\n\n  Usage: ";
  usage += argv[0];
  usage += " [text.fst [binary.fst]]\n";

  std::set_new_handler(FailedNewHandler);
  SET_FLAGS(usage.c_str(), &argc, &argv, true);
  if (argc > 3) {
    ShowUsage();
    return 1;
  }

  const char *source = "standard input";
  istream *istrm = &cin;
  if (argc > 1 && strcmp(argv[1], "-") != 0) {
    source = argv[1];
    istrm = new fst::ifstream(argv[1]);
    if (!*istrm) {
      LOG(ERROR) << argv[0] << ": Open failed, file = " << argv[1];
      return 1;
    }
  }
  const SymbolTable *isyms = 0, *osyms = 0, *ssyms = 0;

  fst::SymbolTableTextOptions opts;
  opts.allow_negative = FLAGS_allow_negative_labels;

  if (!FLAGS_isymbols.empty()) {
    isyms = SymbolTable::ReadText(FLAGS_isymbols, opts);
    if (!isyms) exit(1);
  }

  if (!FLAGS_osymbols.empty()) {
    osyms = SymbolTable::ReadText(FLAGS_osymbols, opts);
    if (!osyms) exit(1);
  }

  if (!FLAGS_ssymbols.empty()) {
    ssyms = SymbolTable::ReadText(FLAGS_ssymbols);
    if (!ssyms) exit(1);
  }

  string dest = argc > 2 ? argv[2] : "";

  s::CompileFst(*istrm, source, dest, FLAGS_fst_type, FLAGS_arc_type,
                isyms, osyms, ssyms,
                FLAGS_acceptor, FLAGS_keep_isymbols, FLAGS_keep_osymbols,
                FLAGS_keep_state_numbering, FLAGS_allow_negative_labels);

  if (istrm != &cin)
    delete istrm;

  return 0;
}
