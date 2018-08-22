// fstsymbols.cc

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
// Performs operations (set, clear, relabel) on the symbols table
// attached to the input Fst.
//

#include <fst/script/fst-class.h>
#include <fst/script/script-impl.h>
#include <fst/script/verify.h>
#include <fst/util.h>

DEFINE_string(isymbols, "", "Input label symbol table");
DEFINE_string(osymbols, "", "Output label symbol table");
DEFINE_bool(clear_isymbols, false, "Clear input symbol table");
DEFINE_bool(clear_osymbols, false, "Clear output symbol table");
DEFINE_string(relabel_ipairs, "", "Input relabel pairs (numeric)");
DEFINE_string(relabel_opairs, "", "Output relabel pairs (numeric)");
DEFINE_string(save_isymbols, "", "Save fst file's input symbol table to file");
DEFINE_string(save_osymbols, "", "Save fst file's output symbol table to file");
DEFINE_bool(allow_negative_labels, false,
            "Allow negative labels (not recommended; may cause conflicts)");
DEFINE_bool(verify, false, "Verify fst properities before saving");

int main(int argc, char **argv) {
  namespace s = fst::script;
  using fst::SymbolTable;

  string usage = "Performs operations (set, clear, relabel) on the symbol"
      " tables attached to an FST.\n\n  Usage: ";
  usage += argv[0];
  usage += " [in.fst [out.fst]]\n";

  std::set_new_handler(FailedNewHandler);
  SET_FLAGS(usage.c_str(), &argc, &argv, true);
  if (argc > 3) {
    ShowUsage();
    return 1;
  }

  string in_fname = argc > 1 && strcmp(argv[1], "-") != 0 ? argv[1] : "";
  string out_fname = argc > 2 ? argv[2] : "";

  s::MutableFstClass *fst = s::MutableFstClass::Read(in_fname, true);
  if (!fst) return 1;

  if (!FLAGS_save_isymbols.empty()) {
    const SymbolTable *isyms = fst->InputSymbols();
    if (isyms) {
      isyms->WriteText(FLAGS_save_isymbols);
    } else {
      LOG(ERROR) << "save isymbols requested but there are no input symbols.";
    }
  }

  if (!FLAGS_save_osymbols.empty()) {
    const SymbolTable *osyms = fst->OutputSymbols();
    if (osyms) {
      osyms->WriteText(FLAGS_save_osymbols);
    } else {
      LOG(ERROR) << "save osymbols requested but there are no output symbols.";
    }
  }

  fst::SymbolTableTextOptions opts;
  opts.allow_negative = FLAGS_allow_negative_labels;

  if (FLAGS_clear_isymbols)
    fst->SetInputSymbols(0);
  else if (!FLAGS_isymbols.empty())
    fst->SetInputSymbols(SymbolTable::ReadText(FLAGS_isymbols, opts));

  if (FLAGS_clear_osymbols)
    fst->SetOutputSymbols(0);
  else if (!FLAGS_osymbols.empty())
    fst->SetOutputSymbols(SymbolTable::ReadText(FLAGS_osymbols, opts));

  if (!FLAGS_relabel_ipairs.empty()) {
    typedef int64 Label;
    vector<pair<Label, Label> > ipairs;
    fst::ReadLabelPairs(FLAGS_relabel_ipairs, &ipairs,
                            FLAGS_allow_negative_labels);
    SymbolTable *isyms = RelabelSymbolTable(fst->InputSymbols(), ipairs);
    fst->SetInputSymbols(isyms);
    delete isyms;
  }

  if (!FLAGS_relabel_opairs.empty()) {
    typedef int64 Label;
    vector<pair<Label, Label> > opairs;
    fst::ReadLabelPairs(FLAGS_relabel_opairs, &opairs,
                            FLAGS_allow_negative_labels);
    SymbolTable *osyms = RelabelSymbolTable(fst->OutputSymbols(), opairs);
    fst->SetOutputSymbols(osyms);
    delete osyms;
  }

  if (FLAGS_verify && !s::Verify(*fst))
    return 1;
  fst->Write(out_fname);
  return 0;
}
