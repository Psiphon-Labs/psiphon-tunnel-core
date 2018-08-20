
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
// Author: riley@google.com (Jake Ratkiewicz)

#include <fst/script/fst-class.h>
#include <fst/script/script-impl.h>
#include <fst/script/disambiguate.h>

namespace fst {
namespace script {

void Disambiguate(const FstClass &ifst,
                 MutableFstClass *ofst,
                 const DisambiguateOptions& opts) {
  if (!ArcTypesMatch(ifst, *ofst, "Disambiguate")) return;

  DisambiguateArgs args(ifst, ofst, opts);
  Apply<Operation<DisambiguateArgs> >("Disambiguate", ifst.ArcType(), &args);
}

REGISTER_FST_OPERATION(Disambiguate, StdArc, DisambiguateArgs);
REGISTER_FST_OPERATION(Disambiguate, LogArc, DisambiguateArgs);
REGISTER_FST_OPERATION(Disambiguate, Log64Arc, DisambiguateArgs);

}  // namespace script
}  // namespace fst
