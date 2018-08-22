
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

#ifndef FST_SCRIPT_DETERMINIZE_H_
#define FST_SCRIPT_DETERMINIZE_H_

#include <fst/determinize.h>
#include <fst/script/arg-packs.h>
#include <fst/script/fst-class.h>
#include <fst/script/weight-class.h>

namespace fst {
namespace script {

struct DeterminizeOptions {
  float delta;
  WeightClass weight_threshold;
  int64 state_threshold;
  int64 subsequential_label;
  bool disambiguate_output;

  explicit DeterminizeOptions(float d = fst::kDelta,
                              WeightClass w =
                                fst::script::WeightClass::Zero(),
                              int64 n = fst::kNoStateId, int64 l = 0,
                              bool o = false)
      : delta(d), weight_threshold(w), state_threshold(n),
        subsequential_label(l), disambiguate_output(o) {}
};

typedef args::Package<const FstClass&, MutableFstClass*,
                      const DeterminizeOptions &> DeterminizeArgs;

template<class Arc>
void Determinize(DeterminizeArgs *args) {
  const Fst<Arc> &ifst = *(args->arg1.GetFst<Arc>());
  MutableFst<Arc> *ofst = args->arg2->GetMutableFst<Arc>();
  const DeterminizeOptions &opts = args->arg3;

  fst::DeterminizeOptions<Arc> detargs;
  detargs.delta = opts.delta;
  detargs.weight_threshold =
      *(opts.weight_threshold.GetWeight<typename Arc::Weight>());
  detargs.state_threshold = opts.state_threshold;
  detargs.subsequential_label = opts.subsequential_label;
  detargs.disambiguate_output = opts.disambiguate_output;

  Determinize(ifst, ofst, detargs);
}

void Determinize(const FstClass &ifst, MutableFstClass *ofst,
                 const DeterminizeOptions &opts =
                   fst::script::DeterminizeOptions());

}  // namespace script
}  // namespace fst

#endif  // FST_SCRIPT_DETERMINIZE_H_
