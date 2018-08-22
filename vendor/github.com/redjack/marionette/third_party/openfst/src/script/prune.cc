
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
#include <fst/script/prune.h>

namespace fst {
namespace script {


// 1
void Prune(MutableFstClass *fst, const PruneOptions &opts) {
  PruneArgs1 args(fst, opts);

  Apply<Operation<PruneArgs1> >("Prune", fst->ArcType(), &args);
}

// 2
void Prune(const FstClass &ifst, MutableFstClass *fst,
           const PruneOptions &opts) {
  PruneArgs2 args(ifst, fst, opts);

  Apply<Operation<PruneArgs2> >("Prune", fst->ArcType(), &args);
}

// 3
void Prune(const FstClass &ifst,
           MutableFstClass *ofst,
           const WeightClass& weight_threshold,
           int64 state_threshold, float delta)  {
  PruneArgs3 args(ifst, ofst, weight_threshold, state_threshold, delta);

  Apply<Operation<PruneArgs3> >("Prune", ifst.ArcType(), &args);
}

// 4
void Prune(MutableFstClass *fst, const WeightClass& weight_threshold,
           int64 state_threshold, float delta) {
  PruneArgs4 args(fst, weight_threshold, state_threshold, delta);

  Apply<Operation<PruneArgs4> >("Prune", fst->ArcType(), &args);
}

// 1
REGISTER_FST_OPERATION(Prune, StdArc, PruneArgs1);
REGISTER_FST_OPERATION(Prune, LogArc, PruneArgs1);
REGISTER_FST_OPERATION(Prune, Log64Arc, PruneArgs1);
// 2
REGISTER_FST_OPERATION(Prune, StdArc, PruneArgs2);
REGISTER_FST_OPERATION(Prune, LogArc, PruneArgs2);
REGISTER_FST_OPERATION(Prune, Log64Arc, PruneArgs2);
// 3
REGISTER_FST_OPERATION(Prune, StdArc, PruneArgs3);
REGISTER_FST_OPERATION(Prune, LogArc, PruneArgs3);
REGISTER_FST_OPERATION(Prune, Log64Arc, PruneArgs3);
// 4
REGISTER_FST_OPERATION(Prune, StdArc, PruneArgs4);
REGISTER_FST_OPERATION(Prune, LogArc, PruneArgs4);
REGISTER_FST_OPERATION(Prune, Log64Arc, PruneArgs4);

}  // namespace script
}  // namespace fst
