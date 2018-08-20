
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
#include <fst/script/synchronize.h>

namespace fst {
namespace script {

void Synchronize(const FstClass &ifst, MutableFstClass *ofst) {
  if (!ArcTypesMatch(ifst, *ofst, "Synchronize")) return;

  SynchronizeArgs args(ifst, ofst);
  Apply<Operation<SynchronizeArgs> >("Synchronize", ifst.ArcType(), &args);
}

REGISTER_FST_OPERATION(Synchronize, StdArc, SynchronizeArgs);
REGISTER_FST_OPERATION(Synchronize, LogArc, SynchronizeArgs);
REGISTER_FST_OPERATION(Synchronize, Log64Arc, SynchronizeArgs);

}  // namespace script
}  // namespace fst
