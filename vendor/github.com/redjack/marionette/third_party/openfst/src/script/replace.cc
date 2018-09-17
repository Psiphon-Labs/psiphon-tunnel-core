
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
#include <fst/script/replace.h>

namespace fst {
namespace script {

void Replace(const vector<pair<int64, const FstClass *> > &tuples,
             MutableFstClass *ofst, const ReplaceOptions& opts) {
  for (unsigned i = 0; i < tuples.size() - 1; ++i) {
    if (!ArcTypesMatch(*tuples[i].second, *tuples[i+1].second, "Replace")) {
      return;
    }
  }

  if (!ArcTypesMatch(*tuples[0].second, *ofst, "Replace")) return;

  ReplaceArgs args(tuples, ofst, opts);

  Apply<Operation<ReplaceArgs> >("Replace", ofst->ArcType(), &args);
}

REGISTER_FST_OPERATION(Replace, StdArc, ReplaceArgs);
REGISTER_FST_OPERATION(Replace, LogArc, ReplaceArgs);
REGISTER_FST_OPERATION(Replace, Log64Arc, ReplaceArgs);

}  // namespace script
}  // namespace fst
