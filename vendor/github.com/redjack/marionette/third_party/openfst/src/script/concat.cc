
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
#include <fst/script/concat.h>

namespace fst {
namespace script {

void Concat(MutableFstClass *ofst, const FstClass &ifst) {
  if (!ArcTypesMatch(*ofst, ifst, "Concat")) return;

  ConcatArgs1 args(ofst, ifst);

  Apply<Operation<ConcatArgs1> >("Concat", ofst->ArcType(), &args);
}

void Concat(const FstClass &ifst, MutableFstClass *ofst) {
  if (!ArcTypesMatch(ifst, *ofst, "Concat")) return;

  ConcatArgs2 args(ifst, ofst);

  Apply<Operation<ConcatArgs2> >("Concat", ofst->ArcType(), &args);
}

REGISTER_FST_OPERATION(Concat, StdArc, ConcatArgs1);
REGISTER_FST_OPERATION(Concat, LogArc, ConcatArgs1);
REGISTER_FST_OPERATION(Concat, Log64Arc, ConcatArgs1);
REGISTER_FST_OPERATION(Concat, StdArc, ConcatArgs2);
REGISTER_FST_OPERATION(Concat, LogArc, ConcatArgs2);
REGISTER_FST_OPERATION(Concat, Log64Arc, ConcatArgs2);

}  // namespace script
}  // namespace fst
