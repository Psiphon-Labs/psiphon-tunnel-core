// fstprint.cc

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
// Prints out binary FSTs in simple text format used by AT&T
// (see http://www.research.att.com/projects/mohri/fsm/doc4/fsm.5.html).

#include <fst/script/print.h>

DEFINE_bool(acceptor, false, "Input in acceptor format");
DEFINE_string(isymbols, "", "Input label symbol table");
DEFINE_string(osymbols, "", "Output label symbol table");
DEFINE_string(ssymbols, "", "State label symbol table");
DEFINE_bool(numeric, false, "Print numeric labels");
DEFINE_string(save_isymbols, "", "Save input symbol table to file");
DEFINE_string(save_osymbols, "", "Save output symbol table to file");
DEFINE_bool(show_weight_one, false,
            "Print/draw arc weights and final weights equal to Weight::One()");
DEFINE_bool(allow_negative_labels, false,
            "Allow negative labels (not recommended; may cause conflicts)");

int main(int argc, char **argv) {
  namespace s = fst::script;
  using fst::ostream;
  using fst::SymbolTable;

  string usage = "Prints out binary FSTs in simple text format.\n\n  Usage: ";
  usage += argv[0];
  usage += " [binary.fst [text.fst]]\n";

  std::set_new_handler(FailedNewHandler);
  SET_FLAGS(usage.c_str(), &argc, &argv, true);
  if (argc > 3) {
    ShowUsage();
    return 1;
  }

  string in_name = (argc > 1 && strcmp(argv[1], "-") != 0) ? argv[1] : "";
  string out_name = argc > 2 ? argv[2] : "";

  s::FstClass *fst = s::FstClass::Read(in_name);
  if (!fst) return 1;

  ostream *ostrm = &cout;
  string dest = "standard output";
  if (argc == 3) {
    dest = argv[2];
    ostrm = new fst::ofstream(argv[2]);
    if (!*ostrm) {
      LOG(ERROR) << argv[0] << ": Open failed, file = " << argv[2];
      return 1;
    }
  }
  ostrm->precision(9);

  const SymbolTable *isyms = 0, *osyms = 0, *ssyms = 0;

  fst::SymbolTableTextOptions opts;
  opts.allow_negative = FLAGS_allow_negative_labels;

  if (!FLAGS_isymbols.empty() && !FLAGS_numeric) {
    isyms = SymbolTable::ReadText(FLAGS_isymbols, opts);
    if (!isyms) exit(1);
  }

  if (!FLAGS_osymbols.empty() && !FLAGS_numeric) {
    osyms = SymbolTable::ReadText(FLAGS_osymbols, opts);
    if (!osyms) exit(1);
  }

  if (!FLAGS_ssymbols.empty() && !FLAGS_numeric) {
    ssyms = SymbolTable::ReadText(FLAGS_ssymbols);
    if (!ssyms) exit(1);
  }

  if (!isyms && !FLAGS_numeric)
    isyms = fst->InputSymbols();
  if (!osyms && !FLAGS_numeric)
    osyms = fst->OutputSymbols();

  s::PrintFst(*fst, *ostrm, dest, isyms, osyms, ssyms,
              FLAGS_acceptor, FLAGS_show_weight_one);

  if (isyms && !FLAGS_save_isymbols.empty())
    isyms->WriteText(FLAGS_save_isymbols);

  if (osyms && !FLAGS_save_osymbols.empty())
    osyms->WriteText(FLAGS_save_osymbols);

  if (ostrm != &cout)
    delete ostrm;
  return 0;
}
