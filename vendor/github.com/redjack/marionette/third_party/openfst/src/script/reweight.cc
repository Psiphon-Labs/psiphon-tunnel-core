
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
#include <fst/script/reweight.h>

namespace fst {
namespace script {

void Reweight(MutableFstClass *fst, const vector<WeightClass> &potential,
              ReweightType reweight_type) {
  ReweightArgs args(fst, potential, reweight_type);

  Apply<Operation<ReweightArgs> >("Reweight", fst->ArcType(), &args);
}

REGISTER_FST_OPERATION(Reweight, StdArc, ReweightArgs);
REGISTER_FST_OPERATION(Reweight, LogArc, ReweightArgs);
REGISTER_FST_OPERATION(Reweight, Log64Arc, ReweightArgs);

}  // namespace script
}  // namespace fst
