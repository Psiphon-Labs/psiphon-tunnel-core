
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
#include <fst/script/rmepsilon.h>

namespace fst {
namespace script {

void RmEpsilon(const FstClass &ifst, MutableFstClass *ofst,
               bool reverse, const RmEpsilonOptions &opts) {
  if (!ArcTypesMatch(ifst, *ofst, "RmEpsilon")) return;

  RmEpsilonArgs1 args(ifst, ofst, reverse, opts);

  Apply<Operation<RmEpsilonArgs1> >("RmEpsilon", ifst.ArcType(), &args);
}

void RmEpsilon(MutableFstClass *fst, bool connect,
               const WeightClass &weight_threshold,
               int64 state_threshold, float delta) {
  RmEpsilonArgs2 args(fst, connect, weight_threshold, state_threshold, delta);

  Apply<Operation<RmEpsilonArgs2> >("RmEpsilon", fst->ArcType(), &args);
}

void RmEpsilon(MutableFstClass *fst, vector<WeightClass> *distance,
               const RmEpsilonOptions &opts) {
  RmEpsilonArgs3 args(fst, distance, opts);

  Apply<Operation<RmEpsilonArgs3> >("RmEpsilon", fst->ArcType(), &args);
}

REGISTER_FST_OPERATION(RmEpsilon, StdArc, RmEpsilonArgs1);
REGISTER_FST_OPERATION(RmEpsilon, LogArc, RmEpsilonArgs1);
REGISTER_FST_OPERATION(RmEpsilon, Log64Arc, RmEpsilonArgs1);

REGISTER_FST_OPERATION(RmEpsilon, StdArc, RmEpsilonArgs2);
REGISTER_FST_OPERATION(RmEpsilon, LogArc, RmEpsilonArgs2);
REGISTER_FST_OPERATION(RmEpsilon, Log64Arc, RmEpsilonArgs2);

REGISTER_FST_OPERATION(RmEpsilon, StdArc, RmEpsilonArgs3);
REGISTER_FST_OPERATION(RmEpsilon, LogArc, RmEpsilonArgs3);
REGISTER_FST_OPERATION(RmEpsilon, Log64Arc, RmEpsilonArgs3);

}  // namespace script
}  // namespace fst
