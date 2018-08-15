
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
#include <fst/script/minimize.h>

namespace fst {
namespace script {

void Minimize(MutableFstClass *ofst1, MutableFstClass *ofst2, float delta) {
  if (ofst2 && !ArcTypesMatch(*ofst1, *ofst2, "Minimize")) return;
  MinimizeArgs args(ofst1, ofst2, delta);

  Apply<Operation<MinimizeArgs> >("Minimize", ofst1->ArcType(), &args);
}

REGISTER_FST_OPERATION(Minimize, StdArc, MinimizeArgs);
REGISTER_FST_OPERATION(Minimize, LogArc, MinimizeArgs);
REGISTER_FST_OPERATION(Minimize, Log64Arc, MinimizeArgs);

}  // namespace script
}  // namespace fst
