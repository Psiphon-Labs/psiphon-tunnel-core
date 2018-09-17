
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

#include <string>

#include <fst/script/fst-class.h>
#include <fst/script/draw.h>
#include <fst/script/script-impl.h>

namespace fst {
namespace script {

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
             const string &dest) {
  FstDrawerArgs args(fst, isyms, osyms, ssyms, accep, title, width,
                     height, portrait, vertical, ranksep, nodesep,
                     fontsize, precision, show_weight_one, ostrm, dest);

  Apply<Operation<FstDrawerArgs> >("DrawFst", fst.ArcType(), &args);
}

REGISTER_FST_OPERATION(DrawFst, StdArc, FstDrawerArgs);
REGISTER_FST_OPERATION(DrawFst, LogArc, FstDrawerArgs);
REGISTER_FST_OPERATION(DrawFst, Log64Arc, FstDrawerArgs);

}  // namespace script
}  // namespace fst
