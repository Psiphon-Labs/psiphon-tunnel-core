
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

#ifndef FST_SCRIPT_RELABEL_H_
#define FST_SCRIPT_RELABEL_H_

#include <utility>
using std::pair; using std::make_pair;
#include <algorithm>
#include <vector>
using std::vector;

#include <fst/script/arg-packs.h>
#include <fst/script/fst-class.h>
#include <fst/relabel.h>

namespace fst {
namespace script {

// 1
typedef args::Package<MutableFstClass *,
                      const SymbolTable *, const SymbolTable *, bool,
                      const SymbolTable *, const SymbolTable *,
                      bool> RelabelArgs1;

template<class Arc>
void Relabel(RelabelArgs1 *args) {
  MutableFst<Arc> *ofst = args->arg1->GetMutableFst<Arc>();

  Relabel(ofst, args->arg2, args->arg3, args->arg4,
          args->arg5, args->arg6, args->arg7);
}

// 2
typedef args::Package<MutableFstClass*,
                      const vector<pair<int64, int64> > &,
                      const vector<pair<int64, int64> > > RelabelArgs2;

template<class Arc>
void Relabel(RelabelArgs2 *args) {
  MutableFst<Arc> *ofst = args->arg1->GetMutableFst<Arc>();

  // In case int64 is not the same as Arc::Label,
  // copy the reassignments
  typedef typename Arc::Label Label;

  vector<pair<Label, Label> > converted_ipairs(args->arg2.size());
  copy(args->arg2.begin(), args->arg2.end(), converted_ipairs.begin());

  vector<pair<Label, Label> > converted_opairs(args->arg3.size());
  copy(args->arg3.begin(), args->arg3.end(), converted_opairs.begin());

  Relabel(ofst, converted_ipairs, converted_opairs);
}

// 3
typedef args::Package<MutableFstClass*, const SymbolTable*,
                      const SymbolTable*> RelabelArgs3;
template<class Arc>
void Relabel(args::Package<MutableFstClass*, const SymbolTable*,
             const SymbolTable*> *args) {
  MutableFst<Arc> *fst = args->arg1->GetMutableFst<Arc>();
  Relabel(fst, args->arg2, args->arg3);
}


// 1
void Relabel(MutableFstClass *ofst,
             const SymbolTable *old_isyms, const SymbolTable *relabel_isyms,
             bool attach_new_isyms,
             const SymbolTable *old_osyms, const SymbolTable *relabel_osyms,
             bool attch_new_osyms);

// 2
void Relabel(MutableFstClass *ofst,
             const vector<pair<int64, int64> > &ipairs,
             const vector<pair<int64, int64> > &opairs);


// 3
void Relabel(MutableFstClass *fst,
             const SymbolTable *new_isymbols,
             const SymbolTable *new_osymbols);


}  // namespace script
}  // namespace fst

#endif  // FST_SCRIPT_RELABEL_H_
