
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
#include <fst/script/intersect.h>

namespace fst {
namespace script {

void Intersect(const FstClass &ifst1, const FstClass &ifst2,
               MutableFstClass *ofst, ComposeFilter compose_filter) {
  if (!ArcTypesMatch(ifst1, ifst2, "Intersect") ||
      !ArcTypesMatch(*ofst, ifst1, "Intersect")) return;

  IntersectArgs1 args(ifst1, ifst2, ofst, compose_filter);
  Apply<Operation<IntersectArgs1> >("Intersect", ifst1.ArcType(), &args);
}

void Intersect(const FstClass &ifst1, const FstClass &ifst2,
               MutableFstClass *ofst, const ComposeOptions &copts) {
  if (!ArcTypesMatch(ifst1, ifst2, "Intersect") ||
      !ArcTypesMatch(*ofst, ifst1, "Intersect")) return;

  IntersectArgs2 args(ifst1, ifst2, ofst, copts);
  Apply<Operation<IntersectArgs2> >("Intersect", ifst1.ArcType(), &args);
}

REGISTER_FST_OPERATION(Intersect, StdArc, IntersectArgs1);
REGISTER_FST_OPERATION(Intersect, LogArc, IntersectArgs1);
REGISTER_FST_OPERATION(Intersect, Log64Arc, IntersectArgs1);
REGISTER_FST_OPERATION(Intersect, StdArc, IntersectArgs2);
REGISTER_FST_OPERATION(Intersect, LogArc, IntersectArgs2);
REGISTER_FST_OPERATION(Intersect, Log64Arc, IntersectArgs2);

}  // namespace script
}  // namespace fst
