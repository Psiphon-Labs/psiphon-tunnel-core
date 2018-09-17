
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

#include <fst/script/fst-class.h>
#include <fst/script/script-impl.h>
#include <fst/script/relabel.h>

namespace fst {
namespace script {

// 1
void Relabel(MutableFstClass *ofst,
             const SymbolTable *old_isyms, const SymbolTable *relabel_isyms,
             bool attach_new_isyms,
             const SymbolTable *old_osyms, const SymbolTable *relabel_osyms,
             bool attach_new_osyms) {
  RelabelArgs1 args(ofst, old_isyms, relabel_isyms, attach_new_isyms,
                         old_osyms, relabel_osyms, attach_new_osyms);
  Apply<Operation<RelabelArgs1> >("Relabel", ofst->ArcType(), &args);
}

// 2
void Relabel(MutableFstClass *ofst,
             const vector<pair<int64, int64> > &ipairs,
             const vector<pair<int64, int64> > &opairs) {
  RelabelArgs2 args(ofst, ipairs, opairs);

  Apply<Operation<RelabelArgs2> >("Relabel", ofst->ArcType(), &args);
}

// 3
void Relabel(MutableFstClass *fst,
             const SymbolTable *new_isymbols,
             const SymbolTable *new_osymbols) {
  RelabelArgs3 args(fst, new_isymbols, new_osymbols);
  Apply<Operation<RelabelArgs3> >("Relabel", fst->ArcType(), &args);
}

// 1
REGISTER_FST_OPERATION(Relabel, StdArc, RelabelArgs1);
REGISTER_FST_OPERATION(Relabel, LogArc, RelabelArgs1);
REGISTER_FST_OPERATION(Relabel, Log64Arc, RelabelArgs1);

// 2
REGISTER_FST_OPERATION(Relabel, StdArc, RelabelArgs2);
REGISTER_FST_OPERATION(Relabel, LogArc, RelabelArgs2);
REGISTER_FST_OPERATION(Relabel, Log64Arc, RelabelArgs2);

// 3
REGISTER_FST_OPERATION(Relabel, StdArc, RelabelArgs3);
REGISTER_FST_OPERATION(Relabel, LogArc, RelabelArgs3);
REGISTER_FST_OPERATION(Relabel, Log64Arc, RelabelArgs3);

}  // namespace script
}  // namespace fst
