
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

#ifndef FST_SCRIPT_COMPILE_H_
#define FST_SCRIPT_COMPILE_H_

#include <fst/script/arg-packs.h>
#include <fst/script/fst-class.h>
#include <fst/script/compile-impl.h>

namespace fst {
namespace script {

// Note: it is safe to pass these strings as references because
// this struct is only used to pass them deeper in the call graph.
// Be sure you understand why this is so before using this struct
// for anything else!
struct FstCompileArgs {
  fst::istream &istrm;
  const string &source;
  const string &dest;
  const string &fst_type;
  const fst::SymbolTable *isyms;
  const fst::SymbolTable *osyms;
  const fst::SymbolTable *ssyms;
  const bool accep;
  const bool ikeep;
  const bool okeep;
  const bool nkeep;
  const bool allow_negative_labels;

  FstCompileArgs(istream &istrm, const string &source, const string &dest,
                 const string &fst_type, const fst::SymbolTable *isyms,
                 const fst::SymbolTable *osyms,
                 const fst::SymbolTable *ssyms,
                 bool accep, bool ikeep, bool okeep, bool nkeep,
                 bool allow_negative_labels = false) :
      istrm(istrm), source(source), dest(dest), fst_type(fst_type),
      isyms(isyms), osyms(osyms), ssyms(ssyms), accep(accep), ikeep(ikeep),
      okeep(okeep), nkeep(nkeep),
      allow_negative_labels(allow_negative_labels) { }
};

template<class Arc>
void CompileFst(FstCompileArgs *args) {
  using fst::FstCompiler;
  using fst::Convert;
  using fst::Fst;

  FstCompiler<Arc> fstcompiler(args->istrm, args->source, args->isyms,
                               args->osyms, args->ssyms,
                               args->accep, args->ikeep,
                               args->okeep, args->nkeep,
                               args->allow_negative_labels);

  const Fst<Arc> *fst = &fstcompiler.Fst();
  if (args->fst_type != "vector") {
    fst = Convert<Arc>(*fst, args->fst_type);
    if (!fst) {
      FSTERROR() << "Failed to convert FST to desired type: "
                 << args->fst_type;
      return;
    }
  }

  fst->Write(args->dest);
}

void CompileFst(istream &istrm, const string &source, const string &dest,
                const string &fst_type, const string &arc_type,
                const SymbolTable *isyms,
                const SymbolTable *osyms, const SymbolTable *ssyms,
                bool accep, bool ikeep, bool okeep, bool nkeep,
                bool allow_negative_labels);

}  // namespace script
}  // namespace fst

#endif  // FST_SCRIPT_COMPILE_H_
