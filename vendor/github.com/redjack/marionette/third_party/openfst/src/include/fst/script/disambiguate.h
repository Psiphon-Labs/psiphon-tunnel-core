
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

#ifndef FST_SCRIPT_DISAMBIGUATE_H_
#define FST_SCRIPT_DISAMBIGUATE_H_

#include <fst/disambiguate.h>
#include <fst/script/arg-packs.h>
#include <fst/script/fst-class.h>
#include <fst/script/weight-class.h>

namespace fst {
namespace script {

struct DisambiguateOptions {
  float delta;
  WeightClass weight_threshold;
  int64 state_threshold;
  int64 subsequential_label;

  explicit DisambiguateOptions(float d = fst::kDelta,
                              WeightClass w =
                                fst::script::WeightClass::Zero(),
                              int64 n = fst::kNoStateId, int64 l = 0)
      : delta(d), weight_threshold(w), state_threshold(n),
        subsequential_label(l) {}
};

typedef args::Package<const FstClass&, MutableFstClass*,
                      const DisambiguateOptions &> DisambiguateArgs;

template<class Arc>
void Disambiguate(DisambiguateArgs *args) {
  const Fst<Arc> &ifst = *(args->arg1.GetFst<Arc>());
  MutableFst<Arc> *ofst = args->arg2->GetMutableFst<Arc>();
  const DisambiguateOptions &opts = args->arg3;

  fst::DisambiguateOptions<Arc> disambargs;
  disambargs.delta = opts.delta;
  disambargs.weight_threshold =
      *(opts.weight_threshold.GetWeight<typename Arc::Weight>());
  disambargs.state_threshold = opts.state_threshold;
  disambargs.subsequential_label = opts.subsequential_label;

  Disambiguate(ifst, ofst, disambargs);
}

void Disambiguate(const FstClass &ifst, MutableFstClass *ofst,
                 const DisambiguateOptions &opts =
                   fst::script::DisambiguateOptions());

}  // namespace script
}  // namespace fst

#endif  // FST_SCRIPT_DISAMBIGUATE_H_
