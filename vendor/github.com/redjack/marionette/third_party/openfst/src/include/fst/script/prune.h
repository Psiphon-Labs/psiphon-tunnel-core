
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

#ifndef FST_SCRIPT_PRUNE_H_
#define FST_SCRIPT_PRUNE_H_

#include <vector>
using std::vector;

#include <fst/script/arg-packs.h>
#include <fst/script/fst-class.h>
#include <fst/script/weight-class.h>
#include <fst/prune.h>
#include <fst/arcfilter.h>

namespace fst {
namespace script {

struct PruneOptions {
  WeightClass weight_threshold;
  int64 state_threshold;
  const vector<WeightClass> *distance;
  float delta;

  explicit PruneOptions(const WeightClass& w, int64 s,
                        vector<WeightClass> *d = 0, float e = kDelta)
      : weight_threshold(w),
        state_threshold(s),
        distance(d),
        delta(e) {}
 private:
  PruneOptions();  // disallow
};

// converts a script::PruneOptions into a fst::PruneOptions.
// Notes:
//  If the original opts.distance is not NULL, a new distance will be
//  created with new; it's the client's responsibility to delete this.

template<class A>
fst::PruneOptions<A, AnyArcFilter<A> > ConvertPruneOptions(
    const PruneOptions &opts) {
  typedef typename A::Weight Weight;
  typedef typename A::StateId StateId;

  Weight weight_threshold = *(opts.weight_threshold.GetWeight<Weight>());
  StateId state_threshold = opts.state_threshold;
  vector<Weight> *distance = 0;

  if (opts.distance) {
    distance = new vector<Weight>(opts.distance->size());
    for (unsigned i = 0; i < opts.distance->size(); ++i) {
      (*distance)[i] = *((*opts.distance)[i].GetWeight<Weight>());
    }
  }

  return fst::PruneOptions<A, AnyArcFilter<A> >(
      weight_threshold, state_threshold, AnyArcFilter<A>(), distance,
      opts.delta);
}

// 1
typedef args::Package<MutableFstClass *, const PruneOptions &> PruneArgs1;

template<class Arc>
void Prune(PruneArgs1 *args) {
  MutableFst<Arc> *ofst = args->arg1->GetMutableFst<Arc>();

  typedef typename Arc::Weight Weight;
  typedef typename Arc::StateId StateId;

  fst::PruneOptions<Arc, AnyArcFilter<Arc> > opts =
      ConvertPruneOptions<Arc>(args->arg2);
  Prune(ofst, opts);
  delete opts.distance;
}

// 2
typedef args::Package<const FstClass &, MutableFstClass *,
                      const PruneOptions &> PruneArgs2;

template<class Arc>
void Prune(PruneArgs2 *args) {
  const Fst<Arc>& ifst = *(args->arg1.GetFst<Arc>());
  MutableFst<Arc> *ofst = args->arg2->GetMutableFst<Arc>();

  fst::PruneOptions<Arc, AnyArcFilter<Arc> > opts =
      ConvertPruneOptions<Arc>(args->arg3);
  Prune(ifst, ofst, opts);
  delete opts.distance;
}

// 3
typedef args::Package<const FstClass &,
                      MutableFstClass *,
                      const WeightClass &, int64, float> PruneArgs3;

template<class Arc>
void Prune(PruneArgs3 *args) {
  const Fst<Arc>& ifst = *(args->arg1.GetFst<Arc>());
  MutableFst<Arc> *ofst = args->arg2->GetMutableFst<Arc>();
  typename Arc::Weight w = *(args->arg3.GetWeight<typename Arc::Weight>());

  Prune(ifst, ofst, w, args->arg4, args->arg5);
}

// 4
typedef args::Package<MutableFstClass *, const WeightClass&,
                      int64, float> PruneArgs4;
template<class Arc>
void Prune(PruneArgs4 *args) {
  MutableFst<Arc> *fst = args->arg1->GetMutableFst<Arc>();
  typename Arc::Weight w = *(args->arg2.GetWeight<typename Arc::Weight>());
  Prune(fst, w, args->arg3, args->arg4);
}


// 1
void Prune(MutableFstClass *fst, const PruneOptions &opts);

// 2
void Prune(const FstClass &ifst, MutableFstClass *fst,
           const PruneOptions &opts);

// 3
void Prune(const FstClass &ifst, MutableFstClass *ofst,
           const WeightClass &weight_threshold,
           int64 state_threshold = kNoStateId,
           float delta = kDelta);

// 4
void Prune(MutableFstClass *fst, const WeightClass& weight_threshold,
           int64 state_threshold, float delta);

}  // namespace script
}  // namespace fst



#endif  // FST_SCRIPT_PRUNE_H_
