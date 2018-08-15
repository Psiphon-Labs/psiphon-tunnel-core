// shortest-path.h

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
// Author: riley@google.com (Michael Riley)
//
// \file
// Functions to find shortest paths in a PDT.

#ifndef FST_EXTENSIONS_PDT_SHORTEST_PATH_H__
#define FST_EXTENSIONS_PDT_SHORTEST_PATH_H__

#include <fst/shortest-path.h>
#include <fst/extensions/pdt/paren.h>
#include <fst/extensions/pdt/pdt.h>

#include <unordered_map>
using std::unordered_map;
using std::unordered_multimap;
#include <unordered_set>
using std::unordered_set;
using std::unordered_multiset;
#include <stack>
#include <vector>
using std::vector;

namespace fst {

template <class Arc, class Queue>
struct PdtShortestPathOptions {
  bool keep_parentheses;
  bool path_gc;

  PdtShortestPathOptions(bool kp = false, bool gc = true)
      : keep_parentheses(kp), path_gc(gc) {}
};


// Class to store PDT shortest path results. Stores shortest path
// tree info 'Distance()', Parent(), and ArcParent() information keyed
// on two types:
// (1) By SearchState: This is a usual node in a shortest path tree but:
//    (a) is w.r.t a PDT search state - a pair of a PDT state and
//        a 'start' state, which is either the PDT start state or
//        the destination state of an open parenthesis.
//    (b) the Distance() is from this 'start' state to the search state.
//    (c) Parent().state is kNoLabel for the 'start' state.
//
// (2) By ParenSpec: This connects shortest path trees depending on the
// the parenthesis taken. Given the parenthesis spec:
//    (a) the Distance() is from the Parent() 'start' state to the
//     parenthesis destination state.
//    (b) the ArcParent() is the parenthesis arc.
template <class Arc>
class PdtShortestPathData {
 public:
  static const uint8 kFinal;

  typedef typename Arc::StateId StateId;
  typedef typename Arc::Weight Weight;
  typedef typename Arc::Label Label;

  struct SearchState {
    SearchState() : state(kNoStateId), start(kNoStateId) {}

    SearchState(StateId s, StateId t) : state(s), start(t) {}

    bool operator==(const SearchState &s) const {
      if (&s == this)
        return true;
      return s.state == this->state && s.start == this->start;
    }

    StateId state;  // PDT state
    StateId start;  // PDT paren 'source' state
  };


  // Specifies paren id, source and dest 'start' states of a paren.
  // These are the 'start' states of the respective sub-graphs.
  struct ParenSpec {
    ParenSpec()
        : paren_id(kNoLabel), src_start(kNoStateId), dest_start(kNoStateId) {}

    ParenSpec(Label id, StateId s, StateId d)
        : paren_id(id), src_start(s), dest_start(d) {}

    Label paren_id;        // Id of parenthesis
    StateId src_start;     // sub-graph 'start' state for paren source.
    StateId dest_start;    // sub-graph 'start' state for paren dest.

    bool operator==(const ParenSpec &x) const {
      if (&x == this)
        return true;
      return x.paren_id == this->paren_id &&
          x.src_start == this->src_start &&
          x.dest_start == this->dest_start;
    }
  };

  struct SearchData {
    SearchData() : distance(Weight::Zero()),
                   parent(kNoStateId, kNoStateId),
                   paren_id(kNoLabel),
                   flags(0) {}

    Weight distance;     // Distance to this state from PDT 'start' state
    SearchState parent;  // Parent state in shortest path tree
    int16 paren_id;      // If parent arc has paren, paren ID, o.w. kNoLabel
    uint8 flags;         // First byte reserved for PdtShortestPathData use
  };

  PdtShortestPathData(bool gc)
      : state_(kNoStateId, kNoStateId),
        paren_(kNoLabel, kNoStateId, kNoStateId),
        gc_(gc),
        nstates_(0),
        ngc_(0),
        finished_(false) {}

  ~PdtShortestPathData() {
    VLOG(1) << "opm size: " << paren_map_.size();
    VLOG(1) << "# of search states: " << nstates_;
    if (gc_)
      VLOG(1) << "# of GC'd search states: " << ngc_;
  }

  void Clear() {
    search_map_.clear();
    search_multimap_.clear();
    paren_map_.clear();
    state_ = SearchState(kNoStateId, kNoStateId);
    nstates_ = 0;
    ngc_ = 0;
  }

  Weight Distance(SearchState s) const {
    SearchData *data = GetSearchData(s);
    return data->distance;
  }

  Weight Distance(const ParenSpec &paren) const {
    SearchData *data = GetSearchData(paren);
    return data->distance;
  }

  SearchState Parent(SearchState s) const {
    SearchData *data = GetSearchData(s);
    return data->parent;
  }

  SearchState Parent(const ParenSpec &paren) const {
    SearchData *data = GetSearchData(paren);
    return data->parent;
  }

  Label ParenId(SearchState s) const {
    SearchData *data = GetSearchData(s);
    return data->paren_id;
  }

  uint8 Flags(SearchState s) const {
    SearchData *data = GetSearchData(s);
    return data->flags;
  }

  void SetDistance(SearchState s, Weight w) {
    SearchData *data = GetSearchData(s);
    data->distance = w;
  }

  void SetDistance(const ParenSpec &paren, Weight w) {
    SearchData *data = GetSearchData(paren);
    data->distance = w;
  }

  void SetParent(SearchState s, SearchState p) {
    SearchData *data = GetSearchData(s);
    data->parent = p;
  }

  void SetParent(const ParenSpec &paren, SearchState p) {
    SearchData *data = GetSearchData(paren);
    data->parent = p;
  }

  void SetParenId(SearchState s, Label p) {
    if (p >= 32768)
      FSTERROR() << "PdtShortestPathData: Paren ID does not fits in an int16";
    SearchData *data = GetSearchData(s);
    data->paren_id = p;
  }

  void SetFlags(SearchState s, uint8 f, uint8 mask) {
    SearchData *data = GetSearchData(s);
    data->flags &= ~mask;
    data->flags |= f & mask;
  }

  void GC(StateId s);

  void Finish() { finished_ = true; }

 private:
  static const Arc kNoArc;
  static const size_t kPrime0;
  static const size_t kPrime1;
  static const uint8 kInited;
  static const uint8 kMarked;

  // Hash for search state
  struct SearchStateHash {
    size_t operator()(const SearchState &s) const {
      return s.state + s.start * kPrime0;
    }
  };

  // Hash for paren map
  struct ParenHash {
    size_t operator()(const ParenSpec &paren) const {
      return paren.paren_id + paren.src_start * kPrime0 +
          paren.dest_start * kPrime1;
    }
  };

  typedef unordered_map<SearchState, SearchData, SearchStateHash> SearchMap;

  typedef unordered_multimap<StateId, StateId> SearchMultimap;

  // Hash map from paren spec to open paren data
  typedef unordered_map<ParenSpec, SearchData, ParenHash> ParenMap;

  SearchData *GetSearchData(SearchState s) const {
    if (s == state_)
      return state_data_;
    if (finished_) {
      typename SearchMap::iterator it = search_map_.find(s);
      if (it == search_map_.end())
        return &null_search_data_;
      state_ = s;
      return state_data_ = &(it->second);
    } else {
      state_ = s;
      state_data_ = &search_map_[s];
      if (!(state_data_->flags & kInited)) {
        ++nstates_;
        if (gc_)
          search_multimap_.insert(make_pair(s.start, s.state));
        state_data_->flags = kInited;
      }
      return state_data_;
    }
  }

  SearchData *GetSearchData(ParenSpec paren) const {
    if (paren == paren_)
      return paren_data_;
    if (finished_) {
      typename ParenMap::iterator it = paren_map_.find(paren);
      if (it == paren_map_.end())
        return &null_search_data_;
      paren_ = paren;
      return state_data_ = &(it->second);
    } else {
      paren_ = paren;
      return paren_data_ = &paren_map_[paren];
    }
  }

  mutable SearchMap search_map_;            // Maps from search state to data
  mutable SearchMultimap search_multimap_;  // Maps from 'start' to subgraph
  mutable ParenMap paren_map_;              // Maps paren spec to search data
  mutable SearchState state_;               // Last state accessed
  mutable SearchData *state_data_;          // Last state data accessed
  mutable ParenSpec paren_;                 // Last paren spec accessed
  mutable SearchData *paren_data_;          // Last paren data accessed
  bool gc_;                                 // Allow GC?
  mutable size_t nstates_;                  // Total number of search states
  size_t ngc_;                              // Number of GC'd search states
  mutable SearchData null_search_data_;     // Null search data
  bool finished_;                           // Read-only access when true

  DISALLOW_COPY_AND_ASSIGN(PdtShortestPathData);
};

// Deletes inaccessible search data from a given 'start' (open paren dest)
// state. Assumes 'final' (close paren source or PDT final) states have
// been flagged 'kFinal'.
template<class Arc>
void  PdtShortestPathData<Arc>::GC(StateId start) {
  if (!gc_)
    return;
  vector<StateId> final;
  for (typename SearchMultimap::iterator mmit = search_multimap_.find(start);
       mmit != search_multimap_.end() && mmit->first == start;
       ++mmit) {
    SearchState s(mmit->second, start);
    const SearchData &data = search_map_[s];
    if (data.flags & kFinal)
      final.push_back(s.state);
  }

  // Mark phase
  for (size_t i = 0; i < final.size(); ++i) {
    SearchState s(final[i], start);
    while (s.state != kNoLabel) {
      SearchData *sdata = &search_map_[s];
      if (sdata->flags & kMarked)
        break;
      sdata->flags |= kMarked;
      SearchState p = sdata->parent;
      if (p.start != start && p.start != kNoLabel) {  // entering sub-subgraph
        ParenSpec paren(sdata->paren_id, s.start, p.start);
        SearchData *pdata = &paren_map_[paren];
        s = pdata->parent;
      } else {
        s = p;
      }
    }
  }

  // Sweep phase
  typename SearchMultimap::iterator mmit = search_multimap_.find(start);
  while (mmit != search_multimap_.end() && mmit->first == start) {
    SearchState s(mmit->second, start);
    typename SearchMap::iterator mit = search_map_.find(s);
    const SearchData &data = mit->second;
    if (!(data.flags & kMarked)) {
      search_map_.erase(mit);
      ++ngc_;
    }
    search_multimap_.erase(mmit++);
  }
}

template<class Arc> const Arc PdtShortestPathData<Arc>::kNoArc
    = Arc(kNoLabel, kNoLabel, Weight::Zero(), kNoStateId);

template<class Arc> const size_t PdtShortestPathData<Arc>::kPrime0 = 7853;

template<class Arc> const size_t PdtShortestPathData<Arc>::kPrime1 = 7867;

template<class Arc> const uint8 PdtShortestPathData<Arc>::kInited = 0x01;

template<class Arc> const uint8 PdtShortestPathData<Arc>::kFinal =  0x02;

template<class Arc> const uint8 PdtShortestPathData<Arc>::kMarked = 0x04;


// This computes the single source shortest (balanced) path (SSSP)
// through a weighted PDT that has a bounded stack (i.e. is expandable
// as an FST). It is a generalization of the classic SSSP graph
// algorithm that removes a state s from a queue (defined by a
// user-provided queue type) and relaxes the destination states of
// transitions leaving s. In this PDT version, states that have
// entering open parentheses are treated as source states for a
// sub-graph SSSP problem with the shortest path up to the open
// parenthesis being first saved. When a close parenthesis is then
// encountered any balancing open parenthesis is examined for this
// saved information and multiplied back. In this way, each sub-graph
// is entered only once rather than repeatedly.  If every state in the
// input PDT has the property that there is a unique 'start' state for
// it with entering open parentheses, then this algorithm is quite
// straight-forward. In general, this will not be the case, so the
// algorithm (implicitly) creates a new graph where each state is a
// pair of an original state and a possible parenthesis 'start' state
// for that state.
template<class Arc, class Queue>
class PdtShortestPath {
 public:
  typedef typename Arc::StateId StateId;
  typedef typename Arc::Weight Weight;
  typedef typename Arc::Label Label;

  typedef PdtShortestPathData<Arc> SpData;
  typedef typename SpData::SearchState SearchState;
  typedef typename SpData::ParenSpec ParenSpec;

  typedef typename PdtBalanceData<Arc>::SetIterator CloseSourceIterator;

  PdtShortestPath(const Fst<Arc> &ifst,
                  const vector<pair<Label, Label> > &parens,
                  const PdtShortestPathOptions<Arc, Queue> &opts)
      : kFinal(SpData::kFinal),
        ifst_(ifst.Copy()),
        parens_(parens),
        keep_parens_(opts.keep_parentheses),
        start_(ifst.Start()),
        sp_data_(opts.path_gc),
        error_(false) {

    if ((Weight::Properties() & (kPath | kRightSemiring))
        != (kPath | kRightSemiring)) {
      FSTERROR() << "PdtShortestPath: Weight needs to have the path"
                 << " property and be right distributive: " << Weight::Type();
      error_ = true;
    }

    for (Label i = 0; i < parens.size(); ++i) {
      const pair<Label, Label>  &p = parens[i];
      paren_id_map_[p.first] = i;
      paren_id_map_[p.second] = i;
    }
  }

  ~PdtShortestPath() {
    VLOG(1) << "# of input states: " << CountStates(*ifst_);
    VLOG(1) << "# of enqueued: " << nenqueued_;
    VLOG(1) << "cpmm size: " << close_paren_multimap_.size();
    delete ifst_;
  }

  void ShortestPath(MutableFst<Arc> *ofst) {
    Init(ofst);
    GetDistance(start_);
    GetPath();
    sp_data_.Finish();
    if (error_) ofst->SetProperties(kError, kError);
  }

  const PdtShortestPathData<Arc> &GetShortestPathData() const {
    return sp_data_;
  }

  PdtBalanceData<Arc> *GetBalanceData() { return &balance_data_; }

 private:
  static const Arc kNoArc;
  static const uint8 kEnqueued;
  static const uint8 kExpanded;
  static const uint8 kFinished;
  const uint8 kFinal;

 public:
  // Hash multimap from close paren label to an paren arc.
  typedef unordered_multimap<ParenState<Arc>, Arc,
                        typename ParenState<Arc>::Hash> CloseParenMultimap;

  const CloseParenMultimap &GetCloseParenMultimap() const {
    return close_paren_multimap_;
  }

 private:
  void Init(MutableFst<Arc> *ofst);
  void GetDistance(StateId start);
  void ProcFinal(SearchState s);
  void ProcArcs(SearchState s);
  void ProcOpenParen(Label paren_id, SearchState s, Arc arc, Weight w);
  void ProcCloseParen(Label paren_id, SearchState s, const Arc &arc, Weight w);
  void ProcNonParen(SearchState s, const Arc &arc, Weight w);
  void Relax(SearchState s, SearchState t, Arc arc, Weight w, Label paren_id);
  void Enqueue(SearchState d);
  void GetPath();
  Arc GetPathArc(SearchState s, SearchState p, Label paren_id, bool open);

  Fst<Arc> *ifst_;
  MutableFst<Arc> *ofst_;
  const vector<pair<Label, Label> > &parens_;
  bool keep_parens_;
  Queue *state_queue_;                   // current state queue
  StateId start_;
  Weight f_distance_;
  SearchState f_parent_;
  SpData sp_data_;
  unordered_map<Label, Label> paren_id_map_;
  CloseParenMultimap close_paren_multimap_;
  PdtBalanceData<Arc> balance_data_;
  ssize_t nenqueued_;
  bool error_;

  DISALLOW_COPY_AND_ASSIGN(PdtShortestPath);
};

template<class Arc, class Queue>
void PdtShortestPath<Arc, Queue>::Init(MutableFst<Arc> *ofst) {
  ofst_ = ofst;
  ofst->DeleteStates();
  ofst->SetInputSymbols(ifst_->InputSymbols());
  ofst->SetOutputSymbols(ifst_->OutputSymbols());

  if (ifst_->Start() == kNoStateId)
    return;

  f_distance_ = Weight::Zero();
  f_parent_ = SearchState(kNoStateId, kNoStateId);

  sp_data_.Clear();
  close_paren_multimap_.clear();
  balance_data_.Clear();
  nenqueued_ = 0;

  // Find open parens per destination state and close parens per source state.
  for (StateIterator<Fst<Arc> > siter(*ifst_); !siter.Done(); siter.Next()) {
    StateId s = siter.Value();
    for (ArcIterator<Fst<Arc> > aiter(*ifst_, s);
         !aiter.Done(); aiter.Next()) {
      const Arc &arc = aiter.Value();
      typename unordered_map<Label, Label>::const_iterator pit
          = paren_id_map_.find(arc.ilabel);
      if (pit != paren_id_map_.end()) {               // Is a paren?
        Label paren_id = pit->second;
        if (arc.ilabel == parens_[paren_id].first) {  // Open paren
          balance_data_.OpenInsert(paren_id, arc.nextstate);
        } else {                                      // Close paren
          ParenState<Arc> paren_state(paren_id, s);
          close_paren_multimap_.insert(make_pair(paren_state, arc));
        }
      }
    }
  }
}

// Computes the shortest distance stored in a recursive way. Each
// sub-graph (i.e. different paren 'start' state) begins with weight One().
template<class Arc, class Queue>
void PdtShortestPath<Arc, Queue>::GetDistance(StateId start) {
  if (start == kNoStateId)
    return;

  Queue state_queue;
  state_queue_ = &state_queue;
  SearchState q(start, start);
  Enqueue(q);
  sp_data_.SetDistance(q, Weight::One());

  while (!state_queue_->Empty()) {
    StateId state = state_queue_->Head();
    state_queue_->Dequeue();
    SearchState s(state, start);
    sp_data_.SetFlags(s, 0, kEnqueued);
    ProcFinal(s);
    ProcArcs(s);
    sp_data_.SetFlags(s, kExpanded, kExpanded);
  }
  sp_data_.SetFlags(q, kFinished, kFinished);
  balance_data_.FinishInsert(start);
  sp_data_.GC(start);
}

// Updates best complete path.
template<class Arc, class Queue>
void PdtShortestPath<Arc, Queue>::ProcFinal(SearchState s) {
  if (ifst_->Final(s.state) != Weight::Zero() && s.start == start_) {
    Weight w = Times(sp_data_.Distance(s),
                     ifst_->Final(s.state));
    if (f_distance_ != Plus(f_distance_, w)) {
      if (f_parent_.state != kNoStateId)
        sp_data_.SetFlags(f_parent_, 0, kFinal);
      sp_data_.SetFlags(s, kFinal, kFinal);

      f_distance_ = Plus(f_distance_, w);
      f_parent_ = s;
    }
  }
}

// Processes all arcs leaving the state s.
template<class Arc, class Queue>
void PdtShortestPath<Arc, Queue>::ProcArcs(SearchState s) {
  for (ArcIterator< Fst<Arc> > aiter(*ifst_, s.state);
       !aiter.Done();
       aiter.Next()) {
    Arc arc = aiter.Value();
    Weight w = Times(sp_data_.Distance(s), arc.weight);

    typename unordered_map<Label, Label>::const_iterator pit
        = paren_id_map_.find(arc.ilabel);
    if (pit != paren_id_map_.end()) {  // Is a paren?
      Label paren_id = pit->second;
      if (arc.ilabel == parens_[paren_id].first)
        ProcOpenParen(paren_id, s, arc, w);
      else
        ProcCloseParen(paren_id, s, arc, w);
    } else {
      ProcNonParen(s, arc, w);
    }
  }
}

// Saves the shortest path info for reaching this parenthesis
// and starts a new SSSP in the sub-graph pointed to by the parenthesis
// if previously unvisited. Otherwise it finds any previously encountered
// closing parentheses and relaxes them using the recursively stored
// shortest distance to them.
template<class Arc, class Queue> inline
void PdtShortestPath<Arc, Queue>::ProcOpenParen(
    Label paren_id, SearchState s, Arc arc, Weight w) {

  SearchState d(arc.nextstate, arc.nextstate);
  ParenSpec paren(paren_id, s.start, d.start);
  Weight pdist = sp_data_.Distance(paren);
  if (pdist != Plus(pdist, w)) {
    sp_data_.SetDistance(paren, w);
    sp_data_.SetParent(paren, s);
    Weight dist = sp_data_.Distance(d);
    if (dist == Weight::Zero()) {
      Queue *state_queue = state_queue_;
      GetDistance(d.start);
      state_queue_ = state_queue;
    } else if (!(sp_data_.Flags(d) & kFinished)) {
      FSTERROR() << "PdtShortestPath: open parenthesis recursion: not bounded stack";
      error_ = true;
    }

    for (CloseSourceIterator set_iter =
             balance_data_.Find(paren_id, arc.nextstate);
         !set_iter.Done(); set_iter.Next()) {
      SearchState cpstate(set_iter.Element(), d.start);
      ParenState<Arc> paren_state(paren_id, cpstate.state);
      for (typename CloseParenMultimap::const_iterator cpit =
               close_paren_multimap_.find(paren_state);
           cpit != close_paren_multimap_.end() && paren_state == cpit->first;
           ++cpit) {
        const Arc &cparc = cpit->second;
        Weight cpw = Times(w, Times(sp_data_.Distance(cpstate),
                                    cparc.weight));
        Relax(cpstate, s, cparc, cpw, paren_id);
      }
    }
  }
}

// Saves the correspondence between each closing parenthesis and its
// balancing open parenthesis info. Relaxes any close parenthesis
// destination state that has a balancing previously encountered open
// parenthesis.
template<class Arc, class Queue> inline
void PdtShortestPath<Arc, Queue>::ProcCloseParen(
    Label paren_id, SearchState s, const Arc &arc, Weight w) {
  ParenState<Arc> paren_state(paren_id, s.start);
  if (!(sp_data_.Flags(s) & kExpanded)) {
    balance_data_.CloseInsert(paren_id, s.start, s.state);
    sp_data_.SetFlags(s, kFinal, kFinal);
  }
}

// For non-parentheses, classical relaxation.
template<class Arc, class Queue> inline
void PdtShortestPath<Arc, Queue>::ProcNonParen(
    SearchState s, const Arc &arc, Weight w) {
  Relax(s, s, arc, w, kNoLabel);
}

// Classical relaxation on the search graph for 'arc' from state 's'.
// State 't' is in the same sub-graph as the nextstate should be (i.e.
// has the same paren 'start'.
template<class Arc, class Queue> inline
void PdtShortestPath<Arc, Queue>::Relax(
    SearchState s, SearchState t, Arc arc, Weight w, Label paren_id) {
  SearchState d(arc.nextstate, t.start);
  Weight dist = sp_data_.Distance(d);
  if (dist != Plus(dist, w)) {
    sp_data_.SetParent(d, s);
    sp_data_.SetParenId(d, paren_id);
    sp_data_.SetDistance(d, Plus(dist, w));
    Enqueue(d);
  }
}

template<class Arc, class Queue> inline
void PdtShortestPath<Arc, Queue>::Enqueue(SearchState s) {
  if (!(sp_data_.Flags(s) & kEnqueued)) {
    state_queue_->Enqueue(s.state);
    sp_data_.SetFlags(s, kEnqueued, kEnqueued);
    ++nenqueued_;
  } else {
    state_queue_->Update(s.state);
  }
}

// Follows parent pointers to find the shortest path. Uses a stack
// since the shortest distance is stored recursively.
template<class Arc, class Queue>
void PdtShortestPath<Arc, Queue>::GetPath() {
  SearchState s = f_parent_, d = SearchState(kNoStateId, kNoStateId);
  StateId s_p = kNoStateId, d_p = kNoStateId;
  Arc arc(kNoArc);
  Label paren_id = kNoLabel;
  stack<ParenSpec> paren_stack;
  while (s.state != kNoStateId) {
    d_p = s_p;
    s_p = ofst_->AddState();
    if (d.state == kNoStateId) {
      ofst_->SetFinal(s_p, ifst_->Final(f_parent_.state));
    } else {
      if (paren_id != kNoLabel) {                     // paren?
        if (arc.ilabel == parens_[paren_id].first) {  // open paren
          paren_stack.pop();
        } else {                                      // close paren
          ParenSpec paren(paren_id, d.start, s.start);
          paren_stack.push(paren);
        }
        if (!keep_parens_)
          arc.ilabel = arc.olabel = 0;
      }
      arc.nextstate = d_p;
      ofst_->AddArc(s_p, arc);
    }
    d = s;
    s = sp_data_.Parent(d);
    paren_id = sp_data_.ParenId(d);
    if (s.state != kNoStateId) {
      arc = GetPathArc(s, d, paren_id, false);
    } else if (!paren_stack.empty()) {
      ParenSpec paren = paren_stack.top();
      s = sp_data_.Parent(paren);
      paren_id = paren.paren_id;
      arc = GetPathArc(s, d, paren_id, true);
    }
  }
  ofst_->SetStart(s_p);
  ofst_->SetProperties(
      ShortestPathProperties(ofst_->Properties(kFstProperties, false)),
      kFstProperties);
}


// Finds transition with least weight between two states with label matching
// paren_id and open/close paren type or a non-paren if kNoLabel.
template<class Arc, class Queue>
Arc PdtShortestPath<Arc, Queue>::GetPathArc(
    SearchState s, SearchState d, Label paren_id, bool open_paren) {
  Arc path_arc = kNoArc;
  for (ArcIterator< Fst<Arc> > aiter(*ifst_, s.state);
       !aiter.Done();
       aiter.Next()) {
    const Arc &arc = aiter.Value();
    if (arc.nextstate != d.state)
      continue;
    Label arc_paren_id = kNoLabel;
    typename unordered_map<Label, Label>::const_iterator pit
        = paren_id_map_.find(arc.ilabel);
    if (pit != paren_id_map_.end()) {
      arc_paren_id = pit->second;
      bool arc_open_paren = arc.ilabel == parens_[arc_paren_id].first;
      if (arc_open_paren != open_paren)
        continue;
    }
    if (arc_paren_id != paren_id)
      continue;
    if (arc.weight == Plus(arc.weight, path_arc.weight))
      path_arc = arc;
  }
  if (path_arc.nextstate == kNoStateId) {
    FSTERROR() << "PdtShortestPath::GetPathArc failed to find arc";
    error_ = true;
  }
  return path_arc;
}

template<class Arc, class Queue>
const Arc PdtShortestPath<Arc, Queue>::kNoArc
    = Arc(kNoLabel, kNoLabel, Weight::Zero(), kNoStateId);

template<class Arc, class Queue>
const uint8 PdtShortestPath<Arc, Queue>::kEnqueued = 0x10;

template<class Arc, class Queue>
const uint8 PdtShortestPath<Arc, Queue>::kExpanded = 0x20;

template<class Arc, class Queue>
const uint8 PdtShortestPath<Arc, Queue>::kFinished = 0x40;

template<class Arc, class Queue>
void ShortestPath(const Fst<Arc> &ifst,
                  const vector<pair<typename Arc::Label,
                                    typename Arc::Label> > &parens,
                  MutableFst<Arc> *ofst,
                  const PdtShortestPathOptions<Arc, Queue> &opts) {
  PdtShortestPath<Arc, Queue> psp(ifst, parens, opts);
  psp.ShortestPath(ofst);
}

template<class Arc>
void ShortestPath(const Fst<Arc> &ifst,
                  const vector<pair<typename Arc::Label,
                                    typename Arc::Label> > &parens,
                  MutableFst<Arc> *ofst) {
  typedef FifoQueue<typename Arc::StateId> Queue;
  PdtShortestPathOptions<Arc, Queue> opts;
  PdtShortestPath<Arc, Queue> psp(ifst, parens, opts);
  psp.ShortestPath(ofst);
}

}  // namespace fst

#endif  // FST_EXTENSIONS_PDT_SHORTEST_PATH_H__
