
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

// Definitions of 'scriptable' versions of pdt operations, that is,
// those that can be called with FstClass-type arguments.

// See comments in nlp/fst/script/script-impl.h for how the registration
// mechanism allows these to work with various arc types.

#include <vector>
using std::vector;
#include <utility>
using std::pair; using std::make_pair;


#include <fst/extensions/pdt/compose.h>
#include <fst/extensions/pdt/expand.h>
#include <fst/extensions/pdt/pdtscript.h>
#include <fst/extensions/pdt/replace.h>
#include <fst/extensions/pdt/reverse.h>
#include <fst/extensions/pdt/shortest-path.h>
#include <fst/script/script-impl.h>

namespace fst {
namespace script {

void PdtCompose(const FstClass &ifst1,
                const FstClass &ifst2,
                const vector<pair<int64, int64> > &parens,
                MutableFstClass *ofst,
                const PdtComposeOptions &copts,
                bool left_pdt) {
  if (!ArcTypesMatch(ifst1, ifst2, "PdtCompose") ||
      !ArcTypesMatch(ifst1, *ofst, "PdtCompose")) return;

  PdtComposeArgs args(ifst1, ifst2, parens, ofst, copts, left_pdt);

  Apply<Operation<PdtComposeArgs> >("PdtCompose", ifst1.ArcType(), &args);
}

void PdtExpand(const FstClass &ifst,
               const vector<pair<int64, int64> > &parens,
               MutableFstClass *ofst, const PdtExpandOptions &opts) {
  PdtExpandArgs args(ifst, parens, ofst, opts);

  Apply<Operation<PdtExpandArgs> >("PdtExpand", ifst.ArcType(), &args);
}

void PdtExpand(const FstClass &ifst,
               const vector<pair<int64, int64> > &parens,
               MutableFstClass *ofst, bool connect) {
  PdtExpand(ifst, parens, ofst, PdtExpandOptions(connect));
}

void PdtReplace(const vector<pair<int64, const FstClass*> > &fst_tuples,
                MutableFstClass *ofst,
                vector<pair<int64, int64> > *parens,
                const int64 &root) {
  for (unsigned i = 0; i < fst_tuples.size() - 1; ++i) {
    if (!ArcTypesMatch(*(fst_tuples[i].second),
                       *(fst_tuples[i+1].second), "PdtReplace")) return;
  }

  if (!ArcTypesMatch((*fst_tuples[0].second), *ofst, "PdtReplace")) return;

  PdtReplaceArgs args(fst_tuples, ofst, parens, root);

  Apply<Operation<PdtReplaceArgs> >("PdtReplace", ofst->ArcType(), &args);
}

void PdtReverse(const FstClass &ifst,
                const vector<pair<int64, int64> > &parens,
                MutableFstClass *ofst) {
  PdtReverseArgs args(ifst, parens, ofst);

  Apply<Operation<PdtReverseArgs> >("PdtReverse", ifst.ArcType(), &args);
}

void PdtShortestPath(const FstClass &ifst,
                     const vector<pair<int64, int64> > &parens,
                     MutableFstClass *ofst,
                     const PdtShortestPathOptions &opts) {
  PdtShortestPathArgs args(ifst, parens, ofst, opts);

  Apply<Operation<PdtShortestPathArgs> >("PdtShortestPath",
                                         ifst.ArcType(), &args);
}

void PrintPdtInfo(const FstClass &ifst,
                  const vector<pair<int64, int64> > &parens) {
  PrintPdtInfoArgs args(ifst, parens);
  Apply<Operation<PrintPdtInfoArgs> >("PrintPdtInfo", ifst.ArcType(), &args);
}

// Register operations for common arc types.

REGISTER_FST_PDT_OPERATIONS(StdArc);
REGISTER_FST_PDT_OPERATIONS(LogArc);
REGISTER_FST_PDT_OPERATIONS(Log64Arc);

}  // namespace script
}  // namespace fst
