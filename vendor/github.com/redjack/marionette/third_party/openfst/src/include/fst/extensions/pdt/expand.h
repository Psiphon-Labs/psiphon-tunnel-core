// expand.h

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
// Expand a PDT to an FST.

#ifndef FST_EXTENSIONS_PDT_EXPAND_H__
#define FST_EXTENSIONS_PDT_EXPAND_H__

#include <forward_list>
using std::forward_list;
#include <vector>
using std::vector;

#include <fst/extensions/pdt/pdt.h>
#include <fst/extensions/pdt/paren.h>
#include <fst/extensions/pdt/shortest-path.h>
#include <fst/extensions/pdt/reverse.h>
#include <fst/cache.h>
#include <fst/mutable-fst.h>
#include <fst/queue.h>
#include <fst/state-table.h>
#include <fst/test-properties.h>

namespace fst {

template <class Arc>
struct ExpandFstOptions : public CacheOptions {
  bool keep_parentheses;
  PdtStack<typename Arc::StateId, typename Arc::Label> *stack;
  PdtStateTable<typename Arc::StateId, typename Arc::StateId> *state_table;

  ExpandFstOptions(
      const CacheOptions &opts = CacheOptions(),
      bool kp = false,
      PdtStack<typename Arc::StateId, typename Arc::Label> *s = 0,
      PdtStateTable<typename Arc::StateId, typename Arc::StateId> *st = 0)
      : CacheOptions(opts), keep_parentheses(kp), stack(s), state_table(st) {}
};

// Properties for an expanded PDT.
inline uint64 ExpandProperties(uint64 inprops) {
  return inprops & (kAcceptor | kAcyclic | kInitialAcyclic | kUnweighted);
}


// Implementation class for ExpandFst
template <class A>
class ExpandFstImpl
    : public CacheImpl<A> {
 public:
  using FstImpl<A>::SetType;
  using FstImpl<A>::SetProperties;
  using FstImpl<A>::Properties;
  using FstImpl<A>::SetInputSymbols;
  using FstImpl<A>::SetOutputSymbols;

  using CacheBaseImpl< CacheState<A> >::PushArc;
  using CacheBaseImpl< CacheState<A> >::HasArcs;
  using CacheBaseImpl< CacheState<A> >::HasFinal;
  using CacheBaseImpl< CacheState<A> >::HasStart;
  using CacheBaseImpl< CacheState<A> >::SetArcs;
  using CacheBaseImpl< CacheState<A> >::SetFinal;
  using CacheBaseImpl< CacheState<A> >::SetStart;

  typedef A Arc;
  typedef typename A::Label Label;
  typedef typename A::Weight Weight;
  typedef typename A::StateId StateId;
  typedef StateId StackId;
  typedef PdtStateTuple<StateId, StackId> StateTuple;

  ExpandFstImpl(const Fst<A> &fst,
                const vector<pair<typename Arc::Label,
                                  typename Arc::Label> > &parens,
                const ExpandFstOptions<A> &opts)
      : CacheImpl<A>(opts), fst_(fst.Copy()),
        stack_(opts.stack ? opts.stack: new PdtStack<StateId, Label>(parens)),
        state_table_(opts.state_table ? opts.state_table :
                     new PdtStateTable<StateId, StackId>()),
        own_stack_(opts.stack == 0), own_state_table_(opts.state_table == 0),
        keep_parentheses_(opts.keep_parentheses) {
    SetType("expand");

    uint64 props = fst.Properties(kFstProperties, false);
    SetProperties(ExpandProperties(props), kCopyProperties);

    SetInputSymbols(fst.InputSymbols());
    SetOutputSymbols(fst.OutputSymbols());
  }

  ExpandFstImpl(const ExpandFstImpl &impl)
      : CacheImpl<A>(impl),
        fst_(impl.fst_->Copy(true)),
        stack_(new PdtStack<StateId, Label>(*impl.stack_)),
        state_table_(new PdtStateTable<StateId, StackId>()),
        own_stack_(true), own_state_table_(true),
        keep_parentheses_(impl.keep_parentheses_) {
    SetType("expand");
    SetProperties(impl.Properties(), kCopyProperties);
    SetInputSymbols(impl.InputSymbols());
    SetOutputSymbols(impl.OutputSymbols());
  }

  ~ExpandFstImpl() {
    delete fst_;
    if (own_stack_)
      delete stack_;
    if (own_state_table_)
      delete state_table_;
  }

  StateId Start() {
    if (!HasStart()) {
      StateId s = fst_->Start();
      if (s == kNoStateId)
        return kNoStateId;
      StateTuple tuple(s, 0);
      StateId start = state_table_->FindState(tuple);
      SetStart(start);
    }
    return CacheImpl<A>::Start();
  }

  Weight Final(StateId s) {
    if (!HasFinal(s)) {
      const StateTuple &tuple = state_table_->Tuple(s);
      Weight w = fst_->Final(tuple.state_id);
      if (w != Weight::Zero() && tuple.stack_id == 0)
        SetFinal(s, w);
      else
        SetFinal(s, Weight::Zero());
    }
    return CacheImpl<A>::Final(s);
  }

  size_t NumArcs(StateId s) {
    if (!HasArcs(s)) {
      ExpandState(s);
    }
    return CacheImpl<A>::NumArcs(s);
  }

  size_t NumInputEpsilons(StateId s) {
    if (!HasArcs(s))
      ExpandState(s);
    return CacheImpl<A>::NumInputEpsilons(s);
  }

  size_t NumOutputEpsilons(StateId s) {
    if (!HasArcs(s))
      ExpandState(s);
    return CacheImpl<A>::NumOutputEpsilons(s);
  }

  void InitArcIterator(StateId s, ArcIteratorData<A> *data) {
    if (!HasArcs(s))
      ExpandState(s);
    CacheImpl<A>::InitArcIterator(s, data);
  }

  // Computes the outgoing transitions from a state, creating new destination
  // states as needed.
  void ExpandState(StateId s) {
    StateTuple tuple = state_table_->Tuple(s);
    for (ArcIterator< Fst<A> > aiter(*fst_, tuple.state_id);
         !aiter.Done(); aiter.Next()) {
      Arc arc = aiter.Value();
      StackId stack_id = stack_->Find(tuple.stack_id, arc.ilabel);
      if (stack_id == -1) {
        // Non-matching close parenthesis
        continue;
      } else if ((stack_id != tuple.stack_id) && !keep_parentheses_) {
        // Stack push/pop
        arc.ilabel = arc.olabel = 0;
      }

      StateTuple ntuple(arc.nextstate, stack_id);
      arc.nextstate = state_table_->FindState(ntuple);
      PushArc(s, arc);
    }
    SetArcs(s);
  }

  const PdtStack<StackId, Label> &GetStack() const { return *stack_; }

  const PdtStateTable<StateId, StackId> &GetStateTable() const {
    return *state_table_;
  }

 private:
  const Fst<A> *fst_;

  PdtStack<StackId, Label> *stack_;
  PdtStateTable<StateId, StackId> *state_table_;
  bool own_stack_;
  bool own_state_table_;
  bool keep_parentheses_;

  void operator=(const ExpandFstImpl<A> &);  // disallow
};

// Expands a pushdown transducer (PDT) encoded as an FST into an FST.
// This version is a delayed Fst.  In the PDT, some transitions are
// labeled with open or close parentheses. To be interpreted as a PDT,
// the parens must balance on a path. The open-close parenthesis label
// pairs are passed in 'parens'. The expansion enforces the
// parenthesis constraints. The PDT must be expandable as an FST.
//
// This class attaches interface to implementation and handles
// reference counting, delegating most methods to ImplToFst.
template <class A>
class ExpandFst : public ImplToFst< ExpandFstImpl<A> > {
 public:
  friend class ArcIterator< ExpandFst<A> >;
  friend class StateIterator< ExpandFst<A> >;

  typedef A Arc;
  typedef typename A::Label Label;
  typedef typename A::Weight Weight;
  typedef typename A::StateId StateId;
  typedef StateId StackId;
  typedef DefaultCacheStore<A> Store;
  typedef typename Store::State State;
  typedef ExpandFstImpl<A> Impl;

  ExpandFst(const Fst<A> &fst,
            const vector<pair<typename Arc::Label,
                              typename Arc::Label> > &parens)
      : ImplToFst<Impl>(new Impl(fst, parens, ExpandFstOptions<A>())) {}

  ExpandFst(const Fst<A> &fst,
            const vector<pair<typename Arc::Label,
                              typename Arc::Label> > &parens,
            const ExpandFstOptions<A> &opts)
      : ImplToFst<Impl>(new Impl(fst, parens, opts)) {}

  // See Fst<>::Copy() for doc.
  ExpandFst(const ExpandFst<A> &fst, bool safe = false)
      : ImplToFst<Impl>(fst, safe) {}

  // Get a copy of this ExpandFst. See Fst<>::Copy() for further doc.
  virtual ExpandFst<A> *Copy(bool safe = false) const {
    return new ExpandFst<A>(*this, safe);
  }

  virtual inline void InitStateIterator(StateIteratorData<A> *data) const;

  virtual void InitArcIterator(StateId s, ArcIteratorData<A> *data) const {
    GetImpl()->InitArcIterator(s, data);
  }

  const PdtStack<StackId, Label> &GetStack() const {
    return GetImpl()->GetStack();
  }

  const PdtStateTable<StateId, StackId> &GetStateTable() const {
    return GetImpl()->GetStateTable();
  }

 private:
  // Makes visible to friends.
  Impl *GetImpl() const { return ImplToFst<Impl>::GetImpl(); }

  void operator=(const ExpandFst<A> &fst);  // Disallow
};


// Specialization for ExpandFst.
template<class A>
class StateIterator< ExpandFst<A> >
    : public CacheStateIterator< ExpandFst<A> > {
 public:
  explicit StateIterator(const ExpandFst<A> &fst)
      : CacheStateIterator< ExpandFst<A> >(fst, fst.GetImpl()) {}
};


// Specialization for ExpandFst.
template <class A>
class ArcIterator< ExpandFst<A> >
    : public CacheArcIterator< ExpandFst<A> > {
 public:
  typedef typename A::StateId StateId;

  ArcIterator(const ExpandFst<A> &fst, StateId s)
      : CacheArcIterator< ExpandFst<A> >(fst.GetImpl(), s) {
    if (!fst.GetImpl()->HasArcs(s))
      fst.GetImpl()->ExpandState(s);
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(ArcIterator);
};


template <class A> inline
void ExpandFst<A>::InitStateIterator(StateIteratorData<A> *data) const
{
  data->base = new StateIterator< ExpandFst<A> >(*this);
}

//
// PrunedExpand Class
//

// Prunes the delayed expansion of a pushdown transducer (PDT) encoded
// as an FST into an FST.  In the PDT, some transitions are labeled
// with open or close parentheses. To be interpreted as a PDT, the
// parens must balance on a path. The open-close parenthesis label
// pairs are passed in 'parens'. The expansion enforces the
// parenthesis constraints.
//
// The algorithm works by visiting the delayed ExpandFst using a
// shortest-stack first queue discipline and relies on the
// shortest-distance information computed using a reverse
// shortest-path call to perform the pruning.
//
// The algorithm maintains the same state ordering between the ExpandFst
// being visited 'efst_' and the result of pruning written into the
// MutableFst 'ofst_' to improve readability of the code.
//
template <class A>
class PrunedExpand {
 public:
  typedef A Arc;
  typedef typename A::Label Label;
  typedef typename A::StateId StateId;
  typedef typename A::Weight Weight;
  typedef StateId StackId;
  typedef PdtStack<StackId, Label> Stack;
  typedef PdtStateTable<StateId, StackId> StateTable;
  typedef typename PdtBalanceData<Arc>::SetIterator SetIterator;

  // Constructor taking as input a PDT specified by 'ifst' and 'parens'.
  // 'keep_parentheses' specifies whether parentheses are replaced by
  // epsilons or not during the expansion. 'opts' is the cache options
  // used to instantiate the underlying ExpandFst.
  PrunedExpand(const Fst<A> &ifst,
               const vector<pair<Label, Label> > &parens,
               bool keep_parentheses = false,
               const CacheOptions &opts = CacheOptions())
      : ifst_(ifst.Copy()),
        keep_parentheses_(keep_parentheses),
        stack_(parens),
        efst_(ifst, parens,
              ExpandFstOptions<Arc>(opts, true, &stack_, &state_table_)),
        queue_(state_table_, stack_, stack_length_, distance_, fdistance_) {
    Reverse(*ifst_, parens, &rfst_);
    VectorFst<Arc> path;
    reverse_shortest_path_ = new SP(
        rfst_, parens,
        PdtShortestPathOptions<A, FifoQueue<StateId> >(true, false));
    reverse_shortest_path_->ShortestPath(&path);
    balance_data_ = reverse_shortest_path_->GetBalanceData()->Reverse(
        rfst_.NumStates(), 10, -1);

    InitCloseParenMultimap(parens);
  }

  ~PrunedExpand() {
    delete ifst_;
    delete reverse_shortest_path_;
    delete balance_data_;
  }

  // Expands and prunes with weight threshold 'threshold' the input PDT.
  // Writes the result in 'ofst'.
  void Expand(MutableFst<A> *ofst, const Weight &threshold);

 private:
  static const uint8 kEnqueued;
  static const uint8 kExpanded;
  static const uint8 kSourceState;

  // Comparison functor used by the queue:
  // 1. states corresponding to shortest stack first,
  // 2. among stacks of the same length, reverse lexicographic order is used,
  // 3. among states with the same stack, shortest-first order is used.
  class StackCompare {
   public:
    StackCompare(const StateTable &st,
                 const Stack &s, const vector<StackId> &sl,
                 const vector<Weight> &d, const vector<Weight> &fd)
        : state_table_(st), stack_(s), stack_length_(sl),
          distance_(d), fdistance_(fd) {}

    bool operator()(StateId s1, StateId s2) const {
      StackId si1 = state_table_.Tuple(s1).stack_id;
      StackId si2 = state_table_.Tuple(s2).stack_id;
      if (stack_length_[si1] < stack_length_[si2])
        return true;
      if  (stack_length_[si1] > stack_length_[si2])
        return false;
      // If stack id equal, use A*
      if (si1 == si2) {
        Weight w1 = (s1 < distance_.size()) && (s1 < fdistance_.size()) ?
            Times(distance_[s1], fdistance_[s1]) : Weight::Zero();
        Weight w2 = (s2 < distance_.size()) && (s2 < fdistance_.size()) ?
            Times(distance_[s2], fdistance_[s2]) : Weight::Zero();
        return less_(w1, w2);
      }
      // If lenghts are equal, use reverse lexico.
      for (; si1 != si2; si1 = stack_.Pop(si1), si2 = stack_.Pop(si2)) {
        if (stack_.Top(si1) < stack_.Top(si2)) return true;
        if (stack_.Top(si1) > stack_.Top(si2)) return false;
      }
      return false;
    }

   private:
    const StateTable &state_table_;
    const Stack &stack_;
    const vector<StackId> &stack_length_;
    const vector<Weight> &distance_;
    const vector<Weight> &fdistance_;
    NaturalLess<Weight> less_;
  };

  class ShortestStackFirstQueue
      : public ShortestFirstQueue<StateId, StackCompare> {
   public:
    ShortestStackFirstQueue(
        const PdtStateTable<StateId, StackId> &st,
        const Stack &s,
        const vector<StackId> &sl,
        const vector<Weight> &d, const vector<Weight> &fd)
        : ShortestFirstQueue<StateId, StackCompare>(
            StackCompare(st, s, sl, d, fd)) {}
  };


  void InitCloseParenMultimap(const vector<pair<Label, Label> > &parens);
  Weight DistanceToDest(StateId state, StateId source) const;
  uint8 Flags(StateId s) const;
  void SetFlags(StateId s, uint8 flags, uint8 mask);
  Weight Distance(StateId s) const;
  void SetDistance(StateId s, Weight w);
  Weight FinalDistance(StateId s) const;
  void SetFinalDistance(StateId s, Weight w);
  StateId SourceState(StateId s) const;
  void SetSourceState(StateId s, StateId p);
  void AddStateAndEnqueue(StateId s);
  void Relax(StateId s, const A &arc, Weight w);
  bool PruneArc(StateId s, const A &arc);
  void ProcStart();
  void ProcFinal(StateId s);
  bool ProcNonParen(StateId s, const A &arc, bool add_arc);
  bool ProcOpenParen(StateId s, const A &arc, StackId si, StackId nsi);
  bool ProcCloseParen(StateId s, const A &arc);
  void ProcDestStates(StateId s, StackId si);

  Fst<A> *ifst_;                   // Input PDT
  VectorFst<Arc> rfst_;            // Reversed PDT
  bool keep_parentheses_;          // Keep parentheses in ofst?
  StateTable state_table_;         // State table for efst_
  Stack stack_;                    // Stack trie
  ExpandFst<Arc> efst_;            // Expanded PDT
  vector<StackId> stack_length_;   // Length of stack for given stack id
  vector<Weight> distance_;        // Distance from initial state in efst_/ofst
  vector<Weight> fdistance_;       // Distance to final states in efst_/ofst
  ShortestStackFirstQueue queue_;  // Queue used to visit efst_
  vector<uint8> flags_;            // Status flags for states in efst_/ofst
  vector<StateId> sources_;        // PDT source state for each expanded state

  typedef PdtShortestPath<Arc, FifoQueue<StateId> > SP;
  typedef typename SP::CloseParenMultimap ParenMultimap;
  SP *reverse_shortest_path_;  // Shortest path for rfst_
  PdtBalanceData<Arc> *balance_data_;   // Not owned by shortest_path_
  ParenMultimap close_paren_multimap_;  // Maps open paren arcs to
  // balancing close paren arcs.

  MutableFst<Arc> *ofst_;  // Output fst
  Weight limit_;           // Weight limit

  typedef unordered_map<StateId, Weight> DestMap;
  DestMap dest_map_;
  StackId current_stack_id_;
  // 'current_stack_id_' is the stack id of the states currently at the top
  // of queue, i.e., the states currently being popped and processed.
  // 'dest_map_' maps a state 's' in 'ifst_' that is the source
  // of a close parentheses matching the top of 'current_stack_id_; to
  // the shortest-distance from '(s, current_stack_id_)' to the final
  // states in 'efst_'.
  ssize_t current_paren_id_;  // Paren id at top of current stack
  ssize_t cached_stack_id_;
  StateId cached_source_;
  std::forward_list<pair<StateId, Weight> > cached_dest_list_;
  // 'cached_dest_list_' contains the set of pair of destination
  // states and weight to final states for source state
  // 'cached_source_' and paren id 'cached_paren_id': the set of
  // source state of a close parenthesis with paren id
  // 'cached_paren_id' balancing an incoming open parenthesis with
  // paren id 'cached_paren_id' in state 'cached_source_'.

  NaturalLess<Weight> less_;
};

template <class A> const uint8 PrunedExpand<A>::kEnqueued = 0x01;
template <class A> const uint8 PrunedExpand<A>::kExpanded = 0x02;
template <class A> const uint8 PrunedExpand<A>::kSourceState = 0x04;


// Initializes close paren multimap, mapping pairs (s,paren_id) to
// all the arcs out of s labeled with close parenthese for paren_id.
template <class A>
void PrunedExpand<A>::InitCloseParenMultimap(
    const vector<pair<Label, Label> > &parens) {
  unordered_map<Label, Label> paren_id_map;
  for (Label i = 0; i < parens.size(); ++i) {
    const pair<Label, Label>  &p = parens[i];
    paren_id_map[p.first] = i;
    paren_id_map[p.second] = i;
  }

  for (StateIterator<Fst<Arc> > siter(*ifst_); !siter.Done(); siter.Next()) {
    StateId s = siter.Value();
    for (ArcIterator<Fst<Arc> > aiter(*ifst_, s);
         !aiter.Done(); aiter.Next()) {
      const Arc &arc = aiter.Value();
      typename unordered_map<Label, Label>::const_iterator pit
          = paren_id_map.find(arc.ilabel);
      if (pit == paren_id_map.end()) continue;
      if (arc.ilabel == parens[pit->second].second) {  // Close paren
        ParenState<Arc> paren_state(pit->second, s);
        close_paren_multimap_.insert(make_pair(paren_state, arc));
      }
    }
  }
}


// Returns the weight of the shortest balanced path from 'source' to 'dest'
// in 'ifst_', 'dest' must be the source state of a close paren arc.
template <class A>
typename A::Weight PrunedExpand<A>::DistanceToDest(StateId source,
                                                   StateId dest) const {
  typename SP::SearchState s(source + 1, dest + 1);
  VLOG(2) << "D(" << source << ", " << dest << ") ="
            << reverse_shortest_path_->GetShortestPathData().Distance(s);
  return reverse_shortest_path_->GetShortestPathData().Distance(s);
}

// Returns the flags for state 's' in 'ofst_'.
template <class A>
uint8 PrunedExpand<A>::Flags(StateId s) const {
  return s < flags_.size() ? flags_[s] : 0;
}

// Modifies the flags for state 's' in 'ofst_'.
template <class A>
void PrunedExpand<A>::SetFlags(StateId s, uint8 flags, uint8 mask) {
  while (flags_.size() <= s) flags_.push_back(0);
  flags_[s] &= ~mask;
  flags_[s] |= flags & mask;
}


// Returns the shortest distance from the initial state to 's' in 'ofst_'.
template <class A>
typename A::Weight PrunedExpand<A>::Distance(StateId s) const {
  return s < distance_.size() ? distance_[s] : Weight::Zero();
}

// Sets the shortest distance from the initial state to 's' in 'ofst_' to 'w'.
template <class A>
void PrunedExpand<A>::SetDistance(StateId s, Weight w) {
  while (distance_.size() <= s ) distance_.push_back(Weight::Zero());
  distance_[s] = w;
}


// Returns the shortest distance from 's' to the final states in 'ofst_'.
template <class A>
typename A::Weight PrunedExpand<A>::FinalDistance(StateId s) const {
  return s < fdistance_.size() ? fdistance_[s] : Weight::Zero();
}

// Sets the shortest distance from 's' to the final states in 'ofst_' to 'w'.
template <class A>
void PrunedExpand<A>::SetFinalDistance(StateId s, Weight w) {
  while (fdistance_.size() <= s) fdistance_.push_back(Weight::Zero());
  fdistance_[s] = w;
}

// Returns the PDT "source" state of state 's' in 'ofst_'.
template <class A>
typename A::StateId PrunedExpand<A>::SourceState(StateId s) const {
  return s < sources_.size() ? sources_[s] : kNoStateId;
}

// Sets the PDT "source" state of state 's' in 'ofst_' to state 'p' in 'ifst_'.
template <class A>
void PrunedExpand<A>::SetSourceState(StateId s, StateId p) {
  while (sources_.size() <= s) sources_.push_back(kNoStateId);
  sources_[s] = p;
}

// Adds state 's' of 'efst_' to 'ofst_' and inserts it in the queue,
// modifying the flags for 's' accordingly.
template <class A>
void PrunedExpand<A>::AddStateAndEnqueue(StateId s) {
  if (!(Flags(s) & (kEnqueued | kExpanded))) {
    while (ofst_->NumStates() <= s) ofst_->AddState();
    queue_.Enqueue(s);
    SetFlags(s, kEnqueued, kEnqueued);
  } else if (Flags(s) & kEnqueued) {
    queue_.Update(s);
  }
  // TODO(allauzen): Check everything is fine when kExpanded?
}

// Relaxes arc 'arc' out of state 's' in 'ofst_':
// * if the distance to 's' times the weight of 'arc' is smaller than
//   the currently stored distance for 'arc.nextstate',
//   updates 'Distance(arc.nextstate)' with new estimate;
// * if 'fd' is less than the currently stored distance from 'arc.nextstate'
//   to the final state, updates with new estimate.
template <class A>
void PrunedExpand<A>::Relax(StateId s, const A &arc, Weight fd) {
  Weight nd = Times(Distance(s), arc.weight);
  if (less_(nd, Distance(arc.nextstate))) {
    SetDistance(arc.nextstate, nd);
    SetSourceState(arc.nextstate, SourceState(s));
  }
  if (less_(fd, FinalDistance(arc.nextstate)))
    SetFinalDistance(arc.nextstate, fd);
  VLOG(2) << "Relax: " << s << ", d[s] = " << Distance(s) << ", to "
            << arc.nextstate << ", d[ns] = " << Distance(arc.nextstate)
            << ", nd = " << nd;
}

// Returns 'true' if the arc 'arc' out of state 's' in 'efst_' needs to
// be pruned.
template <class A>
bool PrunedExpand<A>::PruneArc(StateId s, const A &arc) {
  VLOG(2) << "Prune ?";
  Weight fd = Weight::Zero();

  if ((cached_source_ != SourceState(s)) ||
      (cached_stack_id_ != current_stack_id_)) {
    cached_source_ = SourceState(s);
    cached_stack_id_ = current_stack_id_;
    cached_dest_list_.clear();
    if (cached_source_ != ifst_->Start()) {
      for (SetIterator set_iter =
               balance_data_->Find(current_paren_id_, cached_source_);
           !set_iter.Done(); set_iter.Next()) {
        StateId dest = set_iter.Element();
        typename DestMap::const_iterator iter = dest_map_.find(dest);
        cached_dest_list_.push_front(*iter);
      }
    } else {
      // TODO(allauzen): queue discipline should prevent this never
      // from happening; replace by a check.
      cached_dest_list_.push_front(
          make_pair(rfst_.Start() -1, Weight::One()));
    }
  }

  for (typename std::forward_list<pair<StateId, Weight> >::const_iterator iter =
           cached_dest_list_.begin();
       iter != cached_dest_list_.end(); ++iter) {
    fd = Plus(fd,
              Times(DistanceToDest(state_table_.Tuple(arc.nextstate).state_id,
                                   iter->first),
                    iter->second));
  }
  Relax(s, arc, fd);
  Weight w = Times(Distance(s), Times(arc.weight, fd));
  return less_(limit_, w);
}

// Adds start state of 'efst_' to 'ofst_', enqueues it and initializes
// the distance data structures.
template <class A>
void PrunedExpand<A>::ProcStart() {
  StateId s = efst_.Start();
  AddStateAndEnqueue(s);
  ofst_->SetStart(s);
  SetSourceState(s, ifst_->Start());

  current_stack_id_ = 0;
  current_paren_id_ = -1;
  stack_length_.push_back(0);
  dest_map_[rfst_.Start() - 1] = Weight::One(); // not needed

  cached_source_ = ifst_->Start();
  cached_stack_id_ = 0;
  cached_dest_list_.push_front(
          make_pair(rfst_.Start() -1, Weight::One()));

  PdtStateTuple<StateId, StackId> tuple(rfst_.Start() - 1, 0);
  SetFinalDistance(state_table_.FindState(tuple), Weight::One());
  SetDistance(s, Weight::One());
  SetFinalDistance(s, DistanceToDest(ifst_->Start(), rfst_.Start() - 1));
  VLOG(2) << DistanceToDest(ifst_->Start(), rfst_.Start() - 1);
}

// Makes 's' final in 'ofst_' if shortest accepting path ending in 's'
// is below threshold.
template <class A>
void PrunedExpand<A>::ProcFinal(StateId s) {
  Weight final = efst_.Final(s);
  if ((final == Weight::Zero()) || less_(limit_, Times(Distance(s), final)))
    return;
  ofst_->SetFinal(s, final);
}

// Returns true when arc (or meta-arc) 'arc' out of 's' in 'efst_' is
// below the threshold.  When 'add_arc' is true, 'arc' is added to 'ofst_'.
template <class A>
bool PrunedExpand<A>::ProcNonParen(StateId s, const A &arc, bool add_arc) {
  VLOG(2) << "ProcNonParen: " << s << " to " << arc.nextstate
          << ", " << arc.ilabel << ":" << arc.olabel << " / " << arc.weight
          << ", add_arc = " << (add_arc ? "true" : "false");
  if (PruneArc(s, arc)) return false;
  if(add_arc) ofst_->AddArc(s, arc);
  AddStateAndEnqueue(arc.nextstate);
  return true;
}

// Processes an open paren arc 'arc' out of state 's' in 'ofst_'.
// When 'arc' is labeled with an open paren,
// 1. considers each (shortest) balanced path starting in 's' by
//    taking 'arc' and ending by a close paren balancing the open
//    paren of 'arc' as a meta-arc, processes and prunes each meta-arc
//    as a non-paren arc, inserting its destination to the queue;
// 2. if at least one of these meta-arcs has not been pruned,
//    adds the destination of 'arc' to 'ofst_' as a new source state
//    for the stack id 'nsi' and inserts it in the queue.
template <class A>
bool PrunedExpand<A>::ProcOpenParen(StateId s, const A &arc, StackId si,
                                    StackId nsi) {
  // Update the stack lenght when needed: |nsi| = |si| + 1.
  while (stack_length_.size() <= nsi) stack_length_.push_back(-1);
  if (stack_length_[nsi] == -1)
    stack_length_[nsi] = stack_length_[si] + 1;

  StateId ns = arc.nextstate;
  VLOG(2) << "Open paren: " << s << "(" << state_table_.Tuple(s).state_id
            << ") to " << ns << "(" << state_table_.Tuple(ns).state_id << ")";
  bool proc_arc = false;
  Weight fd = Weight::Zero();
  ssize_t paren_id = stack_.ParenId(arc.ilabel);
  std::forward_list<StateId> sources;
  for (SetIterator set_iter =
           balance_data_->Find(paren_id, state_table_.Tuple(ns).state_id);
       !set_iter.Done(); set_iter.Next()) {
    sources.push_front(set_iter.Element());
  }
  for (typename std::forward_list<StateId>::const_iterator sources_iter =
           sources.begin();
       sources_iter != sources.end(); ++sources_iter) {
    StateId source = *sources_iter;
    VLOG(2) << "Close paren source: " << source;
    ParenState<Arc> paren_state(paren_id, source);
    for (typename ParenMultimap::const_iterator iter =
             close_paren_multimap_.find(paren_state);
         iter != close_paren_multimap_.end() && paren_state == iter->first;
         ++iter) {
      Arc meta_arc = iter->second;
      PdtStateTuple<StateId, StackId> tuple(meta_arc.nextstate, si);
      meta_arc.nextstate =  state_table_.FindState(tuple);
      VLOG(2) << state_table_.Tuple(ns).state_id << ", " << source;
      VLOG(2) << "Meta arc weight = " << arc.weight << " Times "
                << DistanceToDest(state_table_.Tuple(ns).state_id, source)
                << " Times " << meta_arc.weight;
      meta_arc.weight = Times(
          arc.weight,
          Times(DistanceToDest(state_table_.Tuple(ns).state_id, source),
                meta_arc.weight));
      proc_arc |= ProcNonParen(s, meta_arc, false);
      fd = Plus(fd, Times(
          Times(
              DistanceToDest(state_table_.Tuple(ns).state_id, source),
              iter->second.weight),
          FinalDistance(meta_arc.nextstate)));
    }
  }
  if (proc_arc) {
    VLOG(2) << "Proc open paren " << s << " to " << arc.nextstate;
    ofst_->AddArc(
      s, keep_parentheses_ ? arc : Arc(0, 0, arc.weight, arc.nextstate));
    AddStateAndEnqueue(arc.nextstate);
    Weight nd = Times(Distance(s), arc.weight);
    if(less_(nd, Distance(arc.nextstate)))
      SetDistance(arc.nextstate, nd);
    // FinalDistance not necessary for source state since pruning
    // decided using the meta-arcs above.  But this is a problem with
    // A*, hence:
    if (less_(fd, FinalDistance(arc.nextstate)))
      SetFinalDistance(arc.nextstate, fd);
    SetFlags(arc.nextstate, kSourceState, kSourceState);
  }
  return proc_arc;
}

// Checks that shortest path through close paren arc in 'efst_' is
// below threshold, if so adds it to 'ofst_'.
template <class A>
bool PrunedExpand<A>::ProcCloseParen(StateId s, const A &arc) {
  Weight w = Times(Distance(s),
                   Times(arc.weight, FinalDistance(arc.nextstate)));
  if (less_(limit_, w))
    return false;
  ofst_->AddArc(
      s, keep_parentheses_ ? arc : Arc(0, 0, arc.weight, arc.nextstate));
  return true;
}

// When 's' in 'ofst_' is a source state for stack id 'si', identifies
// all the corresponding possible destination states, that is, all the
// states in 'ifst_' that have an outgoing close paren arc balancing
// the incoming open paren taken to get to 's', and for each such
// state 't', computes the shortest distance from (t, si) to the final
// states in 'ofst_'. Stores this information in 'dest_map_'.
template <class A>
void PrunedExpand<A>::ProcDestStates(StateId s, StackId si) {
  if (!(Flags(s) & kSourceState)) return;
  if (si != current_stack_id_) {
    dest_map_.clear();
    current_stack_id_ = si;
    current_paren_id_ = stack_.Top(current_stack_id_);
    VLOG(2) << "StackID " << si << " dequeued for first time";
  }
  // TODO(allauzen): clean up source state business; rename current function to
  // ProcSourceState.
  SetSourceState(s, state_table_.Tuple(s).state_id);

  ssize_t paren_id = stack_.Top(si);
  for (SetIterator set_iter =
           balance_data_->Find(paren_id, state_table_.Tuple(s).state_id);
       !set_iter.Done(); set_iter.Next()) {
    StateId dest_state = set_iter.Element();
    if (dest_map_.find(dest_state) != dest_map_.end())
      continue;
    Weight dest_weight = Weight::Zero();
    ParenState<Arc> paren_state(paren_id, dest_state);
    for (typename ParenMultimap::const_iterator iter =
             close_paren_multimap_.find(paren_state);
         iter != close_paren_multimap_.end() && paren_state == iter->first;
         ++iter) {
      const Arc &arc = iter->second;
      PdtStateTuple<StateId, StackId> tuple(arc.nextstate, stack_.Pop(si));
      dest_weight = Plus(dest_weight,
                         Times(arc.weight,
                               FinalDistance(state_table_.FindState(tuple))));
    }
    dest_map_[dest_state] = dest_weight;
    VLOG(2) << "State " << dest_state << " is a dest state for stack id "
              << si << " with weight " << dest_weight;
  }
}

// Expands and prunes with weight threshold 'threshold' the input PDT.
// Writes the result in 'ofst'.
template <class A>
void PrunedExpand<A>::Expand(
    MutableFst<A> *ofst, const typename A::Weight &threshold) {
  ofst_ = ofst;
  ofst_->DeleteStates();
  ofst_->SetInputSymbols(ifst_->InputSymbols());
  ofst_->SetOutputSymbols(ifst_->OutputSymbols());

  limit_ = Times(DistanceToDest(ifst_->Start(), rfst_.Start() - 1), threshold);
  flags_.clear();

  ProcStart();

  while (!queue_.Empty()) {
    StateId s = queue_.Head();
    queue_.Dequeue();
    SetFlags(s, kExpanded, kExpanded | kEnqueued);
    VLOG(2) << s << " dequeued!";

    ProcFinal(s);
    StackId stack_id = state_table_.Tuple(s).stack_id;
    ProcDestStates(s, stack_id);

    for (ArcIterator<ExpandFst<Arc> > aiter(efst_, s);
         !aiter.Done();
         aiter.Next()) {
      Arc arc = aiter.Value();
      StackId nextstack_id = state_table_.Tuple(arc.nextstate).stack_id;
      if (stack_id == nextstack_id)
        ProcNonParen(s, arc, true);
      else if (stack_id == stack_.Pop(nextstack_id))
        ProcOpenParen(s, arc, stack_id, nextstack_id);
      else
        ProcCloseParen(s, arc);
    }
    VLOG(2) << "d[" << s << "] = " << Distance(s)
            << ", fd[" << s << "] = " << FinalDistance(s);
  }
}

//
// Expand() Functions
//

template <class Arc>
struct ExpandOptions {
  bool connect;
  bool keep_parentheses;
  typename Arc::Weight weight_threshold;

  ExpandOptions(bool c  = true, bool k = false,
                typename Arc::Weight w = Arc::Weight::Zero())
      : connect(c), keep_parentheses(k), weight_threshold(w) {}
};

// Expands a pushdown transducer (PDT) encoded as an FST into an FST.
// This version writes the expanded PDT result to a MutableFst.
// In the PDT, some transitions are labeled with open or close
// parentheses. To be interpreted as a PDT, the parens must balance on
// a path. The open-close parenthesis label pairs are passed in
// 'parens'. The expansion enforces the parenthesis constraints. The
// PDT must be expandable as an FST.
template <class Arc>
void Expand(
    const Fst<Arc> &ifst,
    const vector<pair<typename Arc::Label, typename Arc::Label> > &parens,
    MutableFst<Arc> *ofst,
    const ExpandOptions<Arc> &opts) {
  typedef typename Arc::Label Label;
  typedef typename Arc::StateId StateId;
  typedef typename Arc::Weight Weight;
  typedef typename ExpandFst<Arc>::StackId StackId;

  ExpandFstOptions<Arc> eopts;
  eopts.gc_limit = 0;
  if (opts.weight_threshold == Weight::Zero()) {
    eopts.keep_parentheses = opts.keep_parentheses;
    *ofst = ExpandFst<Arc>(ifst, parens, eopts);
  } else {
    PrunedExpand<Arc> pruned_expand(ifst, parens, opts.keep_parentheses);
    pruned_expand.Expand(ofst, opts.weight_threshold);
  }

  if (opts.connect)
    Connect(ofst);
}

// Expands a pushdown transducer (PDT) encoded as an FST into an FST.
// This version writes the expanded PDT result to a MutableFst.
// In the PDT, some transitions are labeled with open or close
// parentheses. To be interpreted as a PDT, the parens must balance on
// a path. The open-close parenthesis label pairs are passed in
// 'parens'. The expansion enforces the parenthesis constraints. The
// PDT must be expandable as an FST.
template<class Arc>
void Expand(
    const Fst<Arc> &ifst,
    const vector<pair<typename Arc::Label, typename Arc::Label> > &parens,
    MutableFst<Arc> *ofst,
    bool connect = true, bool keep_parentheses = false) {
  Expand(ifst, parens, ofst, ExpandOptions<Arc>(connect, keep_parentheses));
}

}  // namespace fst

#endif  // FST_EXTENSIONS_PDT_EXPAND_H__
