
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

#ifndef FST_SCRIPT_SHORTEST_DISTANCE_H_
#define FST_SCRIPT_SHORTEST_DISTANCE_H_

#include <vector>
using std::vector;

#include <fst/script/arg-packs.h>
#include <fst/script/fst-class.h>
#include <fst/script/weight-class.h>
#include <fst/script/prune.h>  // for ArcFilterType
#include <fst/queue.h>  // for QueueType
#include <fst/shortest-distance.h>

namespace fst {
namespace script {

enum ArcFilterType { ANY_ARC_FILTER, EPSILON_ARC_FILTER,
                     INPUT_EPSILON_ARC_FILTER, OUTPUT_EPSILON_ARC_FILTER };

// See nlp/fst/lib/shortest-distance.h for the template options class
// that this one shadows
struct ShortestDistanceOptions {
  const QueueType queue_type;
  const ArcFilterType arc_filter_type;
  const int64 source;
  const float delta;
  const bool first_path;

  ShortestDistanceOptions(QueueType qt, ArcFilterType aft, int64 s,
                          float d)
      : queue_type(qt), arc_filter_type(aft), source(s), delta(d),
        first_path(false) { }
};



// 1
typedef args::Package<const FstClass &, vector<WeightClass> *,
                      const ShortestDistanceOptions &> ShortestDistanceArgs1;

template<class Queue, class Arc, class ArcFilter>
struct QueueConstructor {
  //  template<class Arc, class ArcFilter>
  static Queue *Construct(const Fst<Arc> &,
                          const vector<typename Arc::Weight> *) {
    return new Queue();
  }
};

// Specializations to deal with AutoQueue, NaturalShortestFirstQueue,
// and TopOrderQueue's different constructors
template<class Arc, class ArcFilter>
struct QueueConstructor<AutoQueue<typename Arc::StateId>, Arc, ArcFilter> {
  //  template<class Arc, class ArcFilter>
  static AutoQueue<typename Arc::StateId> *Construct(
      const Fst<Arc> &fst,
      const vector<typename Arc::Weight> *distance) {
    return new AutoQueue<typename Arc::StateId>(fst, distance, ArcFilter());
  }
};

template<class Arc, class ArcFilter>
struct QueueConstructor<NaturalShortestFirstQueue<typename Arc::StateId,
                                                  typename Arc::Weight>,
                        Arc, ArcFilter> {
  //  template<class Arc, class ArcFilter>
  static NaturalShortestFirstQueue<typename Arc::StateId, typename Arc::Weight>
  *Construct(const Fst<Arc> &fst,
            const vector<typename Arc::Weight> *distance) {
    return new NaturalShortestFirstQueue<typename Arc::StateId,
                                         typename Arc::Weight>(*distance);
  }
};

template<class Arc, class ArcFilter>
struct QueueConstructor<TopOrderQueue<typename Arc::StateId>, Arc, ArcFilter> {
  //  template<class Arc, class ArcFilter>
  static TopOrderQueue<typename Arc::StateId> *Construct(
      const Fst<Arc> &fst, const vector<typename Arc::Weight> *weights) {
    return new TopOrderQueue<typename Arc::StateId>(fst, ArcFilter());
  }
};


template<class Arc, class Queue>
void ShortestDistanceHelper(ShortestDistanceArgs1 *args) {
  const Fst<Arc> &fst = *(args->arg1.GetFst<Arc>());
  const ShortestDistanceOptions &opts = args->arg3;

  vector<typename Arc::Weight> weights;

  switch (opts.arc_filter_type) {
    case ANY_ARC_FILTER: {
      Queue *queue =
          QueueConstructor<Queue, Arc, AnyArcFilter<Arc> >::Construct(
              fst, &weights);
      fst::ShortestDistanceOptions<Arc, Queue, AnyArcFilter<Arc> > sdopts(
          queue, AnyArcFilter<Arc>(), opts.source, opts.delta);
      ShortestDistance(fst, &weights, sdopts);
      delete queue;
      break;
    }
    case EPSILON_ARC_FILTER: {
      Queue *queue =
          QueueConstructor<Queue, Arc, AnyArcFilter<Arc> >::Construct(
              fst, &weights);
      fst::ShortestDistanceOptions<Arc, Queue,
          EpsilonArcFilter<Arc> > sdopts(
              queue, EpsilonArcFilter<Arc>(), opts.source, opts.delta);
      ShortestDistance(fst, &weights, sdopts);
      delete queue;
      break;
    }
    case INPUT_EPSILON_ARC_FILTER: {
      Queue *queue =
          QueueConstructor<Queue, Arc, InputEpsilonArcFilter<Arc> >::Construct(
              fst, &weights);
      fst::ShortestDistanceOptions<Arc, Queue,
          InputEpsilonArcFilter<Arc> > sdopts(
              queue, InputEpsilonArcFilter<Arc>(), opts.source, opts.delta);
      ShortestDistance(fst, &weights, sdopts);
      delete queue;
      break;
    }
    case OUTPUT_EPSILON_ARC_FILTER: {
      Queue *queue =
          QueueConstructor<Queue, Arc,
          OutputEpsilonArcFilter<Arc> >::Construct(
              fst, &weights);
      fst::ShortestDistanceOptions<Arc, Queue,
          OutputEpsilonArcFilter<Arc> > sdopts(
              queue, OutputEpsilonArcFilter<Arc>(), opts.source, opts.delta);
      ShortestDistance(fst, &weights, sdopts);
      delete queue;
      break;
    }
  }

  // Copy the weights back
  args->arg2->resize(weights.size());
  for (unsigned i = 0; i < weights.size(); ++i) {
    (*args->arg2)[i] = WeightClass(weights[i]);
  }
}

template<class Arc>
void ShortestDistance(ShortestDistanceArgs1 *args) {
  const ShortestDistanceOptions &opts = args->arg3;
  typedef typename Arc::StateId StateId;
  typedef typename Arc::Weight Weight;

  // Must consider (opts.queue_type x opts.filter_type) options
  switch (opts.queue_type) {
    default:
      FSTERROR() << "Unknown queue type." << opts.queue_type;

    case AUTO_QUEUE:
      ShortestDistanceHelper<Arc, AutoQueue<StateId> >(args);
      return;

    case FIFO_QUEUE:
      ShortestDistanceHelper<Arc, FifoQueue<StateId> >(args);
      return;

    case LIFO_QUEUE:
      ShortestDistanceHelper<Arc, LifoQueue<StateId> >(args);
      return;

    case SHORTEST_FIRST_QUEUE:
      ShortestDistanceHelper<Arc,
        NaturalShortestFirstQueue<StateId, Weight> >(args);
      return;

    case STATE_ORDER_QUEUE:
      ShortestDistanceHelper<Arc, StateOrderQueue<StateId> >(args);
      return;

    case TOP_ORDER_QUEUE:
      ShortestDistanceHelper<Arc, TopOrderQueue<StateId> >(args);
      return;
  }
}

// 2
typedef args::Package<const FstClass&, vector<WeightClass>*,
                      bool, double> ShortestDistanceArgs2;

template<class Arc>
void ShortestDistance(ShortestDistanceArgs2 *args) {
  const Fst<Arc> &fst = *(args->arg1.GetFst<Arc>());
  vector<typename Arc::Weight> distance;

  ShortestDistance(fst, &distance, args->arg3, args->arg4);

  // convert the typed weights back into weightclass
  vector<WeightClass> *retval = args->arg2;
  retval->resize(distance.size());

  for (unsigned i = 0; i < distance.size(); ++i) {
    (*retval)[i] = WeightClass(distance[i]);
  }
}

// 3
typedef args::WithReturnValue<WeightClass,
                              const FstClass &> ShortestDistanceArgs3;

template<class Arc>
void ShortestDistance(ShortestDistanceArgs3 *args) {
  const Fst<Arc> &fst = *(args->args.GetFst<Arc>());

  args->retval = WeightClass(ShortestDistance(fst));
}


// 1
void ShortestDistance(const FstClass &fst, vector<WeightClass> *distance,
                      const ShortestDistanceOptions &opts);

// 2
void ShortestDistance(const FstClass &ifst, vector<WeightClass> *distance,
                      bool reverse = false, double delta = fst::kDelta);

#ifndef SWIG
// 3
WeightClass ShortestDistance(const FstClass &ifst);
#endif

}  // namespace script
}  // namespace fst



#endif  // FST_SCRIPT_SHORTEST_DISTANCE_H_
