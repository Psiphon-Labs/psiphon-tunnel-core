
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
// Author: jpr@google.com (Jake Ratkiewicz)

#ifndef FST_SCRIPT_PRINT_H_
#define FST_SCRIPT_PRINT_H_

#include <fst/script/arg-packs.h>
#include <fst/script/fst-class.h>
#include <fst/script/print-impl.h>

DECLARE_string(fst_field_separator);

namespace fst {
namespace script {

// Note: it is safe to pass these strings as references because
// this struct is only used to pass them deeper in the call graph.
// Be sure you understand why this is so before using this struct
// for anything else!
struct FstPrinterArgs {
  const FstClass &fst;
  const SymbolTable *isyms;
  const SymbolTable *osyms;
  const SymbolTable *ssyms;
  const bool accept;
  const bool show_weight_one;
  ostream *ostrm;
  const string &dest;
  const string &sep;  // NOLINT

  FstPrinterArgs(const FstClass &fst,
                 const SymbolTable *isyms,
                 const SymbolTable *osyms,
                 const SymbolTable *ssyms,
                 bool accept,
                 bool show_weight_one,
                 ostream *ostrm,
                 const string &dest,
                 const string &sep) :
      fst(fst), isyms(isyms), osyms(osyms), ssyms(ssyms), accept(accept),
      show_weight_one(show_weight_one), ostrm(ostrm), dest(dest), sep(sep) { }
};

template<class Arc>
void PrintFst(FstPrinterArgs *args) {
  const Fst<Arc> &fst = *(args->fst.GetFst<Arc>());

  fst::FstPrinter<Arc> fstprinter(fst, args->isyms, args->osyms,
                                      args->ssyms, args->accept,
                                      args->show_weight_one,
                                      args->sep);
  fstprinter.Print(args->ostrm, args->dest);
}

void PrintFst(const FstClass &fst, ostream &ostrm, const string &dest,
              const SymbolTable *isyms,
              const SymbolTable *osyms,
              const SymbolTable *ssyms,
              bool accept, bool show_weight_one);


// Below are two printing methods with useful defaults for a few of
// the fst printer arguments.
template <class Arc>
void PrintFst(const Fst<Arc> &fst, ostream &os, const string dest = "",
              const SymbolTable *isyms = NULL,
              const SymbolTable *osyms = NULL,
              const SymbolTable *ssyms = NULL) {
  string sep = FLAGS_fst_field_separator.substr(0, 1);
  fst::FstPrinter<Arc> fstprinter(fst, isyms, osyms, ssyms, true, true,
                                      sep);
  fstprinter.Print(&os, dest);
}

}  // namespace script
}  // namespace fst



#endif  // FST_SCRIPT_PRINT_H_
