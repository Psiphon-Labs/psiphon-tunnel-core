
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

#ifndef FST_SCRIPT_DRAW_H_
#define FST_SCRIPT_DRAW_H_

#include <fst/script/arg-packs.h>
#include <fst/script/fst-class.h>
#include <fst/script/draw-impl.h>
#include <iostream>
#include <fstream>
#include <sstream>

namespace fst {
namespace script {

// Note: it is safe to pass these strings as references because
// this struct is only used to pass them deeper in the call graph.
// Be sure you understand why this is so before using this struct
// for anything else!
struct FstDrawerArgs {
  const FstClass &fst;
  const SymbolTable *isyms;
  const SymbolTable *osyms;
  const SymbolTable *ssyms;
  const bool accep;
  const string& title;
  const float width;
  const float height;
  const bool portrait;
  const bool vertical;
  const float ranksep;
  const float nodesep;
  const int fontsize;
  const int precision;
  const bool show_weight_one;
  ostream *ostrm;
  const string &dest;

  FstDrawerArgs(const FstClass &fst,
                const SymbolTable *isyms,
                const SymbolTable *osyms,
                const SymbolTable *ssyms,
                bool accep,
                const string &title,
                float width,
                float height,
                bool portrait,
                bool vertical,
                float ranksep,
                float nodesep,
                int fontsize,
                int precision,
                bool show_weight_one,
                ostream *ostrm,
                const string &dest) :
      fst(fst), isyms(isyms), osyms(osyms), ssyms(ssyms), accep(accep),
      title(title), width(width), height(height), portrait(portrait),
      vertical(vertical), ranksep(ranksep), nodesep(nodesep),
      fontsize(fontsize), precision(precision),
      show_weight_one(show_weight_one), ostrm(ostrm), dest(dest) { }
};


template<class Arc>
void DrawFst(FstDrawerArgs *args) {
  const Fst<Arc> &fst = *(args->fst.GetFst<Arc>());

  FstDrawer<Arc> fstdrawer(fst, args->isyms, args->osyms, args->ssyms,
                           args->accep, args->title, args->width,
                           args->height, args->portrait,
                           args->vertical, args->ranksep,
                           args->nodesep, args->fontsize,
                           args->precision, args->show_weight_one);
  fstdrawer.Draw(args->ostrm, args->dest);
}

void DrawFst(const FstClass &fst,
             const SymbolTable *isyms,
             const SymbolTable *osyms,
             const SymbolTable *ssyms,
             bool accep,
             const string &title,
             float width,
             float height,
             bool portrait,
             bool vertical,
             float ranksep,
             float nodesep,
             int fontsize,
             int precision,
             bool show_weight_one,
             ostream *ostrm,
             const string &dest);

}  // namespace script
}  // namespace fst



#endif  // FST_SCRIPT_DRAW_H_
