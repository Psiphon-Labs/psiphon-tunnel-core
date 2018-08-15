
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

#ifndef FST_SCRIPT_RMEPSILON_H_
#define FST_SCRIPT_RMEPSILON_H_

#include <vector>
using std::vector;

#include <fst/script/arg-packs.h>
#include <fst/script/fst-class.h>
#include <fst/script/weight-class.h>
#include <fst/script/shortest-distance.h>  // for ShortestDistanceOptions
#include <fst/rmepsilon.h>
#include <fst/queue.h>

// the following is necessary, or SWIG complains mightily about
// shortestdistanceoptions not being defined before being used as a base.
#ifdef SWIG
%include "nlp/fst/script/shortest-distance.h"
#endif


namespace fst {
namespace script {

//
// OPTIONS
//

struct RmEpsilonOptions : public fst::script::ShortestDistanceOptions {
  bool connect;
  WeightClass weight_threshold;
  int64 state_threshold;

  RmEpsilonOptions(QueueType qt = AUTO_QUEUE, float d = kDelta, bool c = true,
                   WeightClass w = fst::script::WeightClass::Zero(),
                   int64 n = kNoStateId)
      : ShortestDistanceOptions(qt, EPSILON_ARC_FILTER,
                                kNoStateId, d),
        connect(c), weight_threshold(w), state_threshold(n) { }
};


//
// TEMPLATES
//

// this function takes care of transforming a script-land RmEpsilonOptions
// into a lib-land RmEpsilonOptions
template<class Arc>
void RmEpsilonHelper(MutableFst<Arc> *fst,
                     vector<typename Arc::Weight> *distance,
                     const RmEpsilonOptions &opts) {
  typedef typename Arc::StateId StateId;
  typedef typename Arc::Weight Weight;

  typename Arc::Weight weight_thresh =
      *(opts.weight_threshold.GetWeight<Weight>());

  switch (opts.queue_type) {
    case AUTO_QUEUE: {
      AutoQueue<StateId> queue(*fst, distance, EpsilonArcFilter<Arc>());
      fst::RmEpsilonOptions<Arc, AutoQueue<StateId> > ropts(
          &queue, opts.delta, opts.connect, weight_thresh,
          opts.state_threshold);
      RmEpsilon(fst, distance, ropts);
      break;
    }
    case FIFO_QUEUE: {
      FifoQueue<StateId> queue;
      fst::RmEpsilonOptions<Arc, FifoQueue<StateId> > ropts(
          &queue, opts.delta, opts.connect, weight_thresh,
          opts.state_threshold);
      RmEpsilon(fst, distance, ropts);
      break;
    }
    case LIFO_QUEUE: {
      LifoQueue<StateId> queue;
      fst::RmEpsilonOptions<Arc, LifoQueue<StateId> > ropts(
          &queue, opts.delta, opts.connect, weight_thresh,
          opts.state_threshold);
      RmEpsilon(fst, distance, ropts);
      break;
    }
    case SHORTEST_FIRST_QUEUE: {
      NaturalShortestFirstQueue<StateId, Weight>  queue(*distance);
      fst::RmEpsilonOptions<Arc, NaturalShortestFirstQueue<StateId,
                                                               Weight> > ropts(
          &queue, opts.delta, opts.connect, weight_thresh,
          opts.state_threshold);
      RmEpsilon(fst, distance, ropts);
      break;
    }
    case STATE_ORDER_QUEUE: {
      StateOrderQueue<StateId> queue;
      fst::RmEpsilonOptions<Arc, StateOrderQueue<StateId> > ropts(
          &queue, opts.delta, opts.connect, weight_thresh,
          opts.state_threshold);
      RmEpsilon(fst, distance, ropts);
      break;
    }
    case TOP_ORDER_QUEUE: {
      TopOrderQueue<StateId> queue(*fst, EpsilonArcFilter<Arc>());
      fst::RmEpsilonOptions<Arc, TopOrderQueue<StateId> > ropts(
          &queue, opts.delta, opts.connect, weight_thresh,
          opts.state_threshold);
      RmEpsilon(fst, distance, ropts);
      break;
    }
    default:
      FSTERROR() << "Unknown or unsupported queue type: " << opts.queue_type;
      fst->SetProperties(kError, kError);
  }
}

// 1
typedef args::Package<const FstClass &, MutableFstClass *,
                      bool, const RmEpsilonOptions &> RmEpsilonArgs1;

template<class Arc>
void RmEpsilon(RmEpsilonArgs1 *args) {
  const Fst<Arc> &ifst = *(args->arg1.GetFst<Arc>());
  MutableFst<Arc> *ofst = args->arg2->GetMutableFst<Arc>();
  vector<typename Arc::Weight> distance;
  bool reverse = args->arg3;

  if (reverse) {
    VectorFst<Arc> rfst;
    Reverse(ifst, &rfst);
    RmEpsilonHelper(&rfst, &distance, args->arg4);
    Reverse(rfst, ofst);
  } else {
    *ofst = ifst;
  }
  RmEpsilonHelper(ofst, &distance, args->arg4);
}

// 2
typedef args::Package<MutableFstClass *, bool,
                      const WeightClass, int64,
                      float> RmEpsilonArgs2;

template<class Arc>
void RmEpsilon(RmEpsilonArgs2 *args) {
  MutableFst<Arc> *fst = args->arg1->GetMutableFst<Arc>();
  typename Arc::Weight w = *(args->arg3.GetWeight<typename Arc::Weight>());

  RmEpsilon(fst, args->arg2, w, args->arg4, args->arg5);
}

// 3
typedef args::Package<MutableFstClass *, vector<WeightClass> *,
                      const RmEpsilonOptions &> RmEpsilonArgs3;

template<class Arc>
void RmEpsilon(RmEpsilonArgs3 *args) {
  MutableFst<Arc> *fst = args->arg1->GetMutableFst<Arc>();
  const RmEpsilonOptions &opts = args->arg3;

  vector<typename Arc::Weight> weights;

  RmEpsilonHelper(fst, &weights, opts);

  // Copy the weights back
  args->arg2->resize(weights.size());
  for (unsigned i = 0; i < weights.size(); ++i) {
    (*args->arg2)[i] = WeightClass(weights[i]);
  }
}

//
// PROTOTYPES
//

// 1
void RmEpsilon(const FstClass &ifst, MutableFstClass *ofst,
               bool reverse = false,
               const RmEpsilonOptions& opts =
                 fst::script::RmEpsilonOptions());

// 2
void RmEpsilon(MutableFstClass *arc, bool connect = true,
               const WeightClass &weight_threshold =
                 fst::script::WeightClass::Zero(),
               int64 state_threshold = fst::kNoStateId,
               float delta = fst::kDelta);

// 3
void RmEpsilon(MutableFstClass *fst, vector<WeightClass> *distance,
               const RmEpsilonOptions &opts);


}  // namespace script
}  // namespace fst


#endif  // FST_SCRIPT_RMEPSILON_H_
