
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

#ifndef FST_SCRIPT_SHORTEST_PATH_H_
#define FST_SCRIPT_SHORTEST_PATH_H_

#include <vector>
using std::vector;

#include <fst/script/arg-packs.h>
#include <fst/script/fst-class.h>
#include <fst/script/weight-class.h>
#include <fst/shortest-path.h>
#include <fst/script/shortest-distance.h>  // for ShortestDistanceOptions

namespace fst {
namespace script {

struct ShortestPathOptions
    : public fst::script::ShortestDistanceOptions {
  const size_t nshortest;
  const bool unique;
  const bool has_distance;
  const bool first_path;
  const WeightClass weight_threshold;
  const int64 state_threshold;

  ShortestPathOptions(QueueType qt, size_t n = 1,
                      bool u = false, bool hasdist = false,
                      float d = fst::kDelta, bool fp = false,
                      WeightClass w = fst::script::WeightClass::Zero(),
                      int64 s = fst::kNoStateId)
      : ShortestDistanceOptions(qt, ANY_ARC_FILTER, kNoStateId, d),
        nshortest(n), unique(u), has_distance(hasdist), first_path(fp),
        weight_threshold(w), state_threshold(s) { }
};

typedef args::Package<const FstClass &, MutableFstClass *,
                      vector<WeightClass> *, const ShortestPathOptions &>
  ShortestPathArgs1;


template<class Arc>
void ShortestPath(ShortestPathArgs1 *args) {
  const Fst<Arc> &ifst = *(args->arg1.GetFst<Arc>());
  MutableFst<Arc> *ofst = args->arg2->GetMutableFst<Arc>();
  const ShortestPathOptions &opts = args->arg4;
  typedef typename Arc::StateId StateId;
  typedef typename Arc::Weight Weight;
  typedef AnyArcFilter<Arc> ArcFilter;

  vector<typename Arc::Weight> weights;
  typename Arc::Weight weight_threshold =
      *(opts.weight_threshold.GetWeight<Weight>());

  switch (opts.queue_type) {
    case AUTO_QUEUE: {
      typedef AutoQueue<StateId> Queue;
      Queue *queue = QueueConstructor<Queue, Arc,
          ArcFilter>::Construct(ifst, &weights);
      fst::ShortestPathOptions<Arc, Queue, ArcFilter> spopts(
          queue, ArcFilter(), opts.nshortest, opts.unique,
          opts.has_distance, opts.delta, opts.first_path,
          weight_threshold, opts.state_threshold);
      ShortestPath(ifst, ofst, &weights, spopts);
      delete queue;
      return;
    }
    case FIFO_QUEUE: {
      typedef FifoQueue<StateId> Queue;
      Queue *queue = QueueConstructor<Queue, Arc,
          ArcFilter>::Construct(ifst, &weights);
      fst::ShortestPathOptions<Arc, Queue, ArcFilter> spopts(
          queue, ArcFilter(), opts.nshortest, opts.unique,
          opts.has_distance, opts.delta, opts.first_path,
          weight_threshold, opts.state_threshold);
      ShortestPath(ifst, ofst, &weights, spopts);
      delete queue;
      return;
    }
    case LIFO_QUEUE: {
      typedef LifoQueue<StateId> Queue;
      Queue *queue = QueueConstructor<Queue, Arc,
          ArcFilter >::Construct(ifst, &weights);
      fst::ShortestPathOptions<Arc, Queue, ArcFilter> spopts(
          queue, ArcFilter(), opts.nshortest, opts.unique,
          opts.has_distance, opts.delta, opts.first_path,
          weight_threshold, opts.state_threshold);
      ShortestPath(ifst, ofst, &weights, spopts);
      delete queue;
      return;
    }
    case SHORTEST_FIRST_QUEUE: {
      typedef NaturalShortestFirstQueue<StateId, Weight> Queue;
      Queue *queue = QueueConstructor<Queue, Arc,
          ArcFilter>::Construct(ifst, &weights);
      fst::ShortestPathOptions<Arc, Queue, ArcFilter> spopts(
          queue, ArcFilter(), opts.nshortest, opts.unique,
          opts.has_distance, opts.delta, opts.first_path,
          weight_threshold, opts.state_threshold);
      ShortestPath(ifst, ofst, &weights, spopts);
      delete queue;
      return;
    }
    case STATE_ORDER_QUEUE: {
      typedef StateOrderQueue<StateId> Queue;
      Queue *queue = QueueConstructor<Queue, Arc,
          ArcFilter>::Construct(ifst, &weights);
      fst::ShortestPathOptions<Arc, Queue, ArcFilter> spopts(
          queue, ArcFilter(), opts.nshortest, opts.unique,
          opts.has_distance, opts.delta, opts.first_path,
          weight_threshold, opts.state_threshold);
      ShortestPath(ifst, ofst, &weights, spopts);
      delete queue;
      return;
    }
    case TOP_ORDER_QUEUE: {
      typedef TopOrderQueue<StateId> Queue;
      Queue *queue = QueueConstructor<Queue, Arc,
          ArcFilter>::Construct(ifst, &weights);
      fst::ShortestPathOptions<Arc, Queue, ArcFilter> spopts(
          queue, ArcFilter(), opts.nshortest, opts.unique,
          opts.has_distance, opts.delta, opts.first_path,
          weight_threshold, opts.state_threshold);
      ShortestPath(ifst, ofst, &weights, spopts);
      delete queue;
      return;
    }
    default:
      FSTERROR() << "Unknown queue type: " << opts.queue_type;
      ofst->SetProperties(kError, kError);
  }

  // Copy the weights back
  args->arg3->resize(weights.size());
  for (unsigned i = 0; i < weights.size(); ++i) {
    (*args->arg3)[i] = WeightClass(weights[i]);
  }
}

// 2
typedef args::Package<const FstClass &, MutableFstClass *,
                      size_t, bool, bool, WeightClass,
                      int64> ShortestPathArgs2;

template<class Arc>
void ShortestPath(ShortestPathArgs2 *args) {
  const Fst<Arc> &ifst = *(args->arg1.GetFst<Arc>());
  MutableFst<Arc> *ofst = args->arg2->GetMutableFst<Arc>();
  typename Arc::Weight weight_threshold =
      *(args->arg6.GetWeight<typename Arc::Weight>());

  ShortestPath(ifst, ofst, args->arg3, args->arg4, args->arg5,
               weight_threshold, args->arg7);
}


// 1
void ShortestPath(const FstClass &ifst, MutableFstClass *ofst,
                  vector<WeightClass> *distance,
                  const ShortestPathOptions &opts);


// 2
void ShortestPath(const FstClass &ifst, MutableFstClass *ofst,
                  size_t n = 1, bool unique = false,
                  bool first_path = false,
                  WeightClass weight_threshold =
                    fst::script::WeightClass::Zero(),
                  int64 state_threshold = fst::kNoStateId);

}  // namespace script
}  // namespace fst



#endif  // FST_SCRIPT_SHORTEST_PATH_H_
