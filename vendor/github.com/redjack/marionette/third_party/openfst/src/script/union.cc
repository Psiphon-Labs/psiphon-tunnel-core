
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
#include <fst/script/union.h>

namespace fst {
namespace script {

void Union(MutableFstClass *fst1, const FstClass &fst2) {
  if (!ArcTypesMatch(*fst1, fst2, "Union")) return;

  UnionArgs args(fst1, fst2);

  Apply<Operation<UnionArgs> >("Union", fst1->ArcType(), &args);
}

REGISTER_FST_OPERATION(Union, StdArc, UnionArgs);
REGISTER_FST_OPERATION(Union, LogArc, UnionArgs);
REGISTER_FST_OPERATION(Union, Log64Arc, UnionArgs);

}  // namespace script
}  // namespace fst
