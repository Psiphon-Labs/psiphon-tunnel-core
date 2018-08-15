
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
#include <fst/script/push.h>

namespace fst {
namespace script {

// 1
void Push(MutableFstClass *ofst, ReweightType dir, float delta,
          bool remove_total_weight) {
  PushArgs1 args(ofst, dir, delta, remove_total_weight);
  Apply<Operation<PushArgs1> >("Push", ofst->ArcType(), &args);
}

// 2
void Push(const FstClass &ifst, MutableFstClass *ofst, uint32 flags,
          ReweightType dir, float delta) {
  if (!ArcTypesMatch(ifst, *ofst, "Push")) return;

  PushArgs2 args(ifst, ofst, flags, dir, delta);
  Apply<Operation<PushArgs2> >("Push", ifst.ArcType(), &args);
}


REGISTER_FST_OPERATION(Push, StdArc, PushArgs1);
REGISTER_FST_OPERATION(Push, LogArc, PushArgs1);
REGISTER_FST_OPERATION(Push, Log64Arc, PushArgs1);
REGISTER_FST_OPERATION(Push, StdArc, PushArgs2);
REGISTER_FST_OPERATION(Push, LogArc, PushArgs2);
REGISTER_FST_OPERATION(Push, Log64Arc, PushArgs2);

}  // namespace script
}  // namespace fst
