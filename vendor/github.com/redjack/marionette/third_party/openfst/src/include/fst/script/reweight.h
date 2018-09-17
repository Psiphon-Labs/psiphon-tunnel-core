
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

#ifndef FST_SCRIPT_REWEIGHT_H_
#define FST_SCRIPT_REWEIGHT_H_

#include <vector>
using std::vector;

#include <fst/script/arg-packs.h>
#include <fst/script/fst-class.h>
#include <fst/script/weight-class.h>
#include <fst/reweight.h>

namespace fst {
namespace script {

typedef args::Package<MutableFstClass *, const vector<WeightClass> &,
                      ReweightType> ReweightArgs;

template<class Arc>
void Reweight(ReweightArgs *args) {
  MutableFst<Arc> *fst = args->arg1->GetMutableFst<Arc>();
  typedef typename Arc::Weight Weight;
  vector<Weight> potentials(args->arg2.size());

  for (unsigned i = 0; i < args->arg2.size(); ++i) {
    potentials[i] = *(args->arg2[i].GetWeight<Weight>());
  }

  Reweight(fst, potentials, args->arg3);
}

void Reweight(MutableFstClass *fst, const vector<WeightClass> &potential,
              ReweightType reweight_type);

}  // namespace script
}  // namespace fst

#endif  // FST_SCRIPT_REWEIGHT_H_
