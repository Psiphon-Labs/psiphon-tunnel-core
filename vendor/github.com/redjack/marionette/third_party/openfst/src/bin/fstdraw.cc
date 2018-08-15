// fstdraw.cc

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
// Draws a binary FSTs in the Graphviz dot text format

#include <fst/script/draw.h>

DEFINE_bool(acceptor, false, "Input in acceptor format");
DEFINE_string(isymbols, "", "Input label symbol table");
DEFINE_string(osymbols, "", "Output label symbol table");
DEFINE_string(ssymbols, "", "State label symbol table");
DEFINE_bool(numeric, false, "Print numeric labels");
DEFINE_int32(precision, 5, "Set precision (number of char/float)");
DEFINE_bool(show_weight_one, false,
            "Print/draw arc weights and final weights equal to Weight::One()");
DEFINE_string(title, "", "Set figure title");
DEFINE_bool(portrait, false, "Portrait mode (def: landscape)");
DEFINE_bool(vertical, false, "Draw bottom-to-top instead of left-to-right");
DEFINE_int32(fontsize, 14, "Set fontsize");
DEFINE_double(height, 11, "Set height");
DEFINE_double(width, 8.5, "Set width");
DEFINE_double(nodesep, 0.25,
              "Set minimum separation between nodes (see dot documentation)");
DEFINE_double(ranksep, 0.40,
              "Set minimum separation between ranks (see dot documentation)");
DEFINE_bool(allow_negative_labels, false,
            "Allow negative labels (not recommended; may cause conflicts)");

int main(int argc, char **argv) {
  namespace s = fst::script;
  using fst::ostream;
  using fst::SymbolTable;

  string usage = "Prints out binary FSTs in dot text format.\n\n  Usage: ";
  usage += argv[0];
  usage += " [binary.fst [text.dot]]\n";

  std::set_new_handler(FailedNewHandler);
  SET_FLAGS(usage.c_str(), &argc, &argv, true);
  if (argc > 3) {
    ShowUsage();
    return 1;
  }

  string in_name = (argc > 1 && strcmp(argv[1], "-") != 0) ? argv[1] : "";

  s::FstClass *fst = s::FstClass::Read(in_name);
  if (!fst) return 1;

  ostream *ostrm = &cout;
  string dest = "stdout";
  if (argc == 3) {
    dest = argv[2];
    ostrm = new fst::ofstream(argv[2]);
    if (!*ostrm) {
      LOG(ERROR) << argv[0] << ": Open failed, file = " << argv[2];
      return 1;
    }
  }
  ostrm->precision(FLAGS_precision);

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

  s::DrawFst(*fst, isyms, osyms, ssyms,  FLAGS_acceptor,
             FLAGS_title, FLAGS_width, FLAGS_height,
             FLAGS_portrait, FLAGS_vertical,
             FLAGS_ranksep, FLAGS_nodesep,
             FLAGS_fontsize, FLAGS_precision,
             FLAGS_show_weight_one, ostrm, dest);

  if (ostrm != &cout)
    delete ostrm;
  return 0;
}
