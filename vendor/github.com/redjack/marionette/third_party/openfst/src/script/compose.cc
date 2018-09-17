
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
#include <fst/script/compose.h>

namespace fst {
namespace script {


void Compose(const FstClass &ifst1, const FstClass &ifst2,
             MutableFstClass *ofst, ComposeFilter compose_filter) {
  if (!ArcTypesMatch(ifst1, ifst2, "Compose") ||
      !ArcTypesMatch(*ofst, ifst1, "Compose")) return;

  ComposeArgs1 args(ifst1, ifst2, ofst, compose_filter);
  Apply<Operation<ComposeArgs1> >("Compose", ifst1.ArcType(), &args);
}

void Compose(const FstClass &ifst1, const FstClass &ifst2,
             MutableFstClass *ofst, const ComposeOptions &copts) {
  if (!ArcTypesMatch(ifst1, ifst2, "Compose") ||
      !ArcTypesMatch(*ofst, ifst1, "Compose")) return;

  ComposeArgs2 args(ifst1, ifst2, ofst, copts);
  Apply<Operation<ComposeArgs2> >("Compose", ifst1.ArcType(), &args);
}

REGISTER_FST_OPERATION(Compose, StdArc, ComposeArgs1);
REGISTER_FST_OPERATION(Compose, LogArc, ComposeArgs1);
REGISTER_FST_OPERATION(Compose, Log64Arc, ComposeArgs1);
REGISTER_FST_OPERATION(Compose, StdArc, ComposeArgs2);
REGISTER_FST_OPERATION(Compose, LogArc, ComposeArgs2);
REGISTER_FST_OPERATION(Compose, Log64Arc, ComposeArgs2);

}  // namespace script
}  // namespace fst
