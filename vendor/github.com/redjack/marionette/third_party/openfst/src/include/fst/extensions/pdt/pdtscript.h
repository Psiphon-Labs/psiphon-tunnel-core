
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
// Convenience file for including all PDT operations at once, and/or
// registering them for new arc types.

#ifndef FST_EXTENSIONS_PDT_PDTSCRIPT_H_
#define FST_EXTENSIONS_PDT_PDTSCRIPT_H_

#include <utility>
using std::pair; using std::make_pair;
#include <vector>
using std::vector;

#include <fst/compose.h>  // for ComposeOptions
#include <fst/util.h>

#include <fst/script/fst-class.h>
#include <fst/script/arg-packs.h>
#include <fst/script/shortest-path.h>

#include <fst/extensions/pdt/compose.h>
#include <fst/extensions/pdt/expand.h>
#include <fst/extensions/pdt/info.h>
#include <fst/extensions/pdt/replace.h>
#include <fst/extensions/pdt/reverse.h>
#include <fst/extensions/pdt/shortest-path.h>


namespace fst {
namespace script {

// PDT COMPOSE

typedef args::Package<const FstClass &,
                      const FstClass &,
                      const vector<pair<int64, int64> >&,
                      MutableFstClass *,
                      const PdtComposeOptions &,
                      bool> PdtComposeArgs;

template<class Arc>
void PdtCompose(PdtComposeArgs *args) {
  const Fst<Arc> &ifst1 = *(args->arg1.GetFst<Arc>());
  const Fst<Arc> &ifst2 = *(args->arg2.GetFst<Arc>());
  MutableFst<Arc> *ofst = args->arg4->GetMutableFst<Arc>();

  vector<pair<typename Arc::Label, typename Arc::Label> > parens(
      args->arg3.size());

  for (size_t i = 0; i < parens.size(); ++i) {
    parens[i].first = args->arg3[i].first;
    parens[i].second = args->arg3[i].second;
  }

  if (args->arg6) {
    Compose(ifst1, parens, ifst2, ofst, args->arg5);
  } else {
    Compose(ifst1, ifst2, parens, ofst, args->arg5);
  }
}

void PdtCompose(const FstClass & ifst1,
                const FstClass & ifst2,
                const vector<pair<int64, int64> > &parens,
                MutableFstClass *ofst,
                const PdtComposeOptions &copts,
                bool left_pdt);

// PDT EXPAND

struct PdtExpandOptions {
  bool connect;
  bool keep_parentheses;
  WeightClass weight_threshold;

  PdtExpandOptions(bool c = true, bool k = false,
                   WeightClass w = WeightClass::Zero())
      : connect(c), keep_parentheses(k), weight_threshold(w) {}
};

typedef args::Package<const FstClass &,
                      const vector<pair<int64, int64> >&,
                      MutableFstClass *, PdtExpandOptions> PdtExpandArgs;

template<class Arc>
void PdtExpand(PdtExpandArgs *args) {
  const Fst<Arc> &fst = *(args->arg1.GetFst<Arc>());
  MutableFst<Arc> *ofst = args->arg3->GetMutableFst<Arc>();

  vector<pair<typename Arc::Label, typename Arc::Label> > parens(
      args->arg2.size());
  for (size_t i = 0; i < parens.size(); ++i) {
    parens[i].first = args->arg2[i].first;
    parens[i].second = args->arg2[i].second;
  }
  Expand(fst, parens, ofst,
         ExpandOptions<Arc>(
             args->arg4.connect, args->arg4.keep_parentheses,
             *(args->arg4.weight_threshold.GetWeight<typename Arc::Weight>())));
}

void PdtExpand(const FstClass &ifst,
               const vector<pair<int64, int64> > &parens,
               MutableFstClass *ofst, const PdtExpandOptions &opts);

void PdtExpand(const FstClass &ifst,
               const vector<pair<int64, int64> > &parens,
               MutableFstClass *ofst, bool connect);

// PDT REPLACE

typedef args::Package<const vector<pair<int64, const FstClass*> > &,
                      MutableFstClass *,
                      vector<pair<int64, int64> > *,
                      const int64 &> PdtReplaceArgs;
template<class Arc>
void PdtReplace(PdtReplaceArgs *args) {
  vector<pair<typename Arc::Label, const Fst<Arc> *> > tuples(
      args->arg1.size());
  for (size_t i = 0; i < tuples.size(); ++i) {
    tuples[i].first = args->arg1[i].first;
    tuples[i].second = (args->arg1[i].second)->GetFst<Arc>();
  }
  MutableFst<Arc> *ofst = args->arg2->GetMutableFst<Arc>();
  vector<pair<typename Arc::Label, typename Arc::Label> > parens(
      args->arg3->size());

  for (size_t i = 0; i < parens.size(); ++i) {
    parens[i].first = args->arg3->at(i).first;
    parens[i].second = args->arg3->at(i).second;
  }
  Replace(tuples, ofst, &parens, args->arg4);

  // now copy parens back
  args->arg3->resize(parens.size());
  for (size_t i = 0; i < parens.size(); ++i) {
    (*args->arg3)[i].first = parens[i].first;
    (*args->arg3)[i].second = parens[i].second;
  }
}

void PdtReplace(const vector<pair<int64, const FstClass*> > &fst_tuples,
                MutableFstClass *ofst,
                vector<pair<int64, int64> > *parens,
                const int64 &root);

// PDT REVERSE

typedef args::Package<const FstClass &,
                      const vector<pair<int64, int64> >&,
                      MutableFstClass *> PdtReverseArgs;

template<class Arc>
void PdtReverse(PdtReverseArgs *args) {
  const Fst<Arc> &fst = *(args->arg1.GetFst<Arc>());
  MutableFst<Arc> *ofst = args->arg3->GetMutableFst<Arc>();

  vector<pair<typename Arc::Label, typename Arc::Label> > parens(
      args->arg2.size());
  for (size_t i = 0; i < parens.size(); ++i) {
    parens[i].first = args->arg2[i].first;
    parens[i].second = args->arg2[i].second;
  }
  Reverse(fst, parens, ofst);
}

void PdtReverse(const FstClass &ifst,
                const vector<pair<int64, int64> > &parens,
                MutableFstClass *ofst);


// PDT SHORTESTPATH

struct PdtShortestPathOptions {
  QueueType queue_type;
  bool keep_parentheses;
  bool path_gc;

  PdtShortestPathOptions(QueueType qt = FIFO_QUEUE,
                         bool kp = false, bool gc = true)
      : queue_type(qt), keep_parentheses(kp), path_gc(gc) {}
};

typedef args::Package<const FstClass &,
                      const vector<pair<int64, int64> >&,
                      MutableFstClass *,
                      const PdtShortestPathOptions &> PdtShortestPathArgs;

template<class Arc>
void PdtShortestPath(PdtShortestPathArgs *args) {
  typedef typename Arc::StateId StateId;
  typedef typename Arc::Label Label;
  typedef typename Arc::Weight Weight;

  const Fst<Arc> &fst = *(args->arg1.GetFst<Arc>());
  MutableFst<Arc> *ofst = args->arg3->GetMutableFst<Arc>();
  const PdtShortestPathOptions &opts = args->arg4;


  vector<pair<Label, Label> > parens(args->arg2.size());
  for (size_t i = 0; i < parens.size(); ++i) {
    parens[i].first = args->arg2[i].first;
    parens[i].second = args->arg2[i].second;
  }

  switch (opts.queue_type) {
    default:
      FSTERROR() << "Unknown queue type: " << opts.queue_type;
    case FIFO_QUEUE: {
      typedef FifoQueue<StateId> Queue;
      fst::PdtShortestPathOptions<Arc, Queue> spopts(opts.keep_parentheses,
                                                         opts.path_gc);
      ShortestPath(fst, parens, ofst, spopts);
      return;
    }
    case LIFO_QUEUE: {
      typedef LifoQueue<StateId> Queue;
      fst::PdtShortestPathOptions<Arc, Queue> spopts(opts.keep_parentheses,
                                                         opts.path_gc);
      ShortestPath(fst, parens, ofst, spopts);
      return;
    }
    case STATE_ORDER_QUEUE: {
      typedef StateOrderQueue<StateId> Queue;
      fst::PdtShortestPathOptions<Arc, Queue> spopts(opts.keep_parentheses,
                                                         opts.path_gc);
      ShortestPath(fst, parens, ofst, spopts);
      return;
    }
  }
}

void PdtShortestPath(const FstClass &ifst,
                     const vector<pair<int64, int64> > &parens,
                     MutableFstClass *ofst,
                     const PdtShortestPathOptions &opts =
                     PdtShortestPathOptions());

// PRINT INFO

typedef args::Package<const FstClass &,
                      const vector<pair<int64, int64> > &> PrintPdtInfoArgs;

template<class Arc>
void PrintPdtInfo(PrintPdtInfoArgs *args) {
  const Fst<Arc> &fst = *(args->arg1.GetFst<Arc>());
  vector<pair<typename Arc::Label, typename Arc::Label> > parens(
      args->arg2.size());
  for (size_t i = 0; i < parens.size(); ++i) {
    parens[i].first = args->arg2[i].first;
    parens[i].second = args->arg2[i].second;
  }
  PdtInfo<Arc> pdtinfo(fst, parens);
  PrintPdtInfo(pdtinfo);
}

void PrintPdtInfo(const FstClass &ifst,
                  const vector<pair<int64, int64> > &parens);

}  // namespace script
}  // namespace fst


#define REGISTER_FST_PDT_OPERATIONS(ArcType)                                \
  REGISTER_FST_OPERATION(PdtCompose, ArcType, PdtComposeArgs);              \
  REGISTER_FST_OPERATION(PdtExpand, ArcType, PdtExpandArgs);                \
  REGISTER_FST_OPERATION(PdtReplace, ArcType, PdtReplaceArgs);              \
  REGISTER_FST_OPERATION(PdtReverse, ArcType, PdtReverseArgs);              \
  REGISTER_FST_OPERATION(PdtShortestPath, ArcType, PdtShortestPathArgs);    \
  REGISTER_FST_OPERATION(PrintPdtInfo, ArcType, PrintPdtInfoArgs)
#endif  // FST_EXTENSIONS_PDT_PDTSCRIPT_H_
