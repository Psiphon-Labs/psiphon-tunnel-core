// fstrelabel.cc

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
// Author: johans@google.com (Johan Schalkwyk)
// Modified: jpr@google.com (Jake Ratkiewicz) to use FstClass
//
// \file
// Relabel input or output space of Fst
//

#include <string>
#include <vector>
using std::vector;
#include <utility>
using std::pair; using std::make_pair;

#include <fst/script/relabel.h>
#include <fst/script/weight-class.h>
#include <fst/util.h>

DEFINE_string(isymbols, "", "Input label symbol table");
DEFINE_string(osymbols, "", "Output label symbol table");
DEFINE_string(relabel_isymbols, "", "Input symbol set to relabel to");
DEFINE_string(relabel_osymbols, "", "Ouput symbol set to relabel to");
DEFINE_string(relabel_ipairs, "", "Input relabel pairs (numeric)");
DEFINE_string(relabel_opairs, "", "Output relabel pairs (numeric)");

DEFINE_bool(allow_negative_labels, false,
            "Allow negative labels (not recommended; may cause conflicts)");

int main(int argc, char **argv) {
  namespace s = fst::script;
  using fst::SymbolTable;
  using fst::SymbolTableTextOptions;
  using fst::script::FstClass;
  using fst::script::MutableFstClass;

  string usage = "Relabels the input and/or the output labels of the FST.\n\n"
      "  Usage: ";
  usage += argv[0];
  usage += " [in.fst [out.fst]]\n";
  usage += " Using SymbolTables flags:\n";
  usage += "  -relabel_isymbols isyms.txt\n";
  usage += "  -relabel_osymbols osyms.txt\n";
  usage += " Using numeric labels flags:\n";
  usage += "  -relabel_ipairs   ipairs.txt\n";
  usage += "  -relabel_opairs   opairs.txts\n";

  std::set_new_handler(FailedNewHandler);
  SET_FLAGS(usage.c_str(), &argc, &argv, true);
  if (argc > 3) {
    ShowUsage();
    return 1;
  }

  string in_name = (argc > 1 && (strcmp(argv[1], "-") != 0)) ? argv[1] : "";
  string out_name = argc > 2 ? argv[2] : "";

  MutableFstClass *fst = MutableFstClass::Read(in_name, true);
  if (!fst) return 1;

  // Relabel with symbol tables
  SymbolTableTextOptions opts;
  opts.allow_negative = FLAGS_allow_negative_labels;
  if (!FLAGS_relabel_isymbols.empty() || !FLAGS_relabel_osymbols.empty()) {
    bool attach_new_isymbols = (fst->InputSymbols() != 0);
    const SymbolTable* old_isymbols = FLAGS_isymbols.empty()
        ? fst->InputSymbols()
        : SymbolTable::ReadText(FLAGS_isymbols, opts);
    const SymbolTable* relabel_isymbols = FLAGS_relabel_isymbols.empty()
        ? NULL
        : SymbolTable::ReadText(FLAGS_relabel_isymbols, opts);

    bool attach_new_osymbols = (fst->OutputSymbols() != 0);
    const SymbolTable* old_osymbols = FLAGS_osymbols.empty()
        ? fst->OutputSymbols()
        : SymbolTable::ReadText(FLAGS_osymbols, opts);
    const SymbolTable* relabel_osymbols = FLAGS_relabel_osymbols.empty()
        ? NULL
        : SymbolTable::ReadText(FLAGS_relabel_osymbols, opts);

    s::Relabel(fst,
               old_isymbols, relabel_isymbols, attach_new_isymbols,
               old_osymbols, relabel_osymbols, attach_new_osymbols);
  } else {
    // read in relabel pairs and parse
    typedef int64 Label;
    vector<pair<Label, Label> > ipairs;
    vector<pair<Label, Label> > opairs;
    if (!FLAGS_relabel_ipairs.empty()) {
      if(!fst::ReadLabelPairs(FLAGS_relabel_ipairs, &ipairs,
                                  FLAGS_allow_negative_labels))
        return 1;
    }
    if (!FLAGS_relabel_opairs.empty()) {
      if (!fst::ReadLabelPairs(FLAGS_relabel_opairs, &opairs,
                                   FLAGS_allow_negative_labels))
        return 1;
    }
    s::Relabel(fst, ipairs, opairs);
  }

  fst->Write(out_name);

  return 0;
}
