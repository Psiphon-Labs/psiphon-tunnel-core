// paren.h

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
// Common classes for PDT parentheses

// \file

#ifndef FST_EXTENSIONS_PDT_PAREN_H_
#define FST_EXTENSIONS_PDT_PAREN_H_

#include <algorithm>
#include <unordered_map>
using std::unordered_map;
using std::unordered_multimap;
#include <unordered_set>
using std::unordered_set;
using std::unordered_multiset;
#include <set>

#include <fst/extensions/pdt/pdt.h>
#include <fst/extensions/pdt/collection.h>
#include <fst/fst.h>
#include <fst/dfs-visit.h>


namespace fst {

//
// ParenState: Pair of an open (close) parenthesis and
// its destination (source) state.
//

template <class A>
class ParenState {
 public:
  typedef typename A::Label Label;
  typedef typename A::StateId StateId;

  struct Hash {
    size_t operator()(const ParenState<A> &p) const {
      return p.paren_id + p.state_id * kPrime;
    }
  };

  Label paren_id;     // ID of open (close) paren
  StateId state_id;   // destination (source) state of open (close) paren

  ParenState() : paren_id(kNoLabel), state_id(kNoStateId) {}

  ParenState(Label p, StateId s) : paren_id(p), state_id(s) {}

  bool operator==(const ParenState<A> &p) const {
    if (&p == this)
      return true;
    return p.paren_id == this->paren_id && p.state_id == this->state_id;
  }

  bool operator!=(const ParenState<A> &p) const { return !(p == *this); }

  bool operator<(const ParenState<A> &p) const {
    return paren_id < this->paren.id ||
        (p.paren_id == this->paren.id && p.state_id < this->state_id);
  }

 private:
  static const size_t kPrime;
};

template <class A>
const size_t ParenState<A>::kPrime = 7853;


// Creates an FST-style iterator from STL map and iterator.
template <class M>
class MapIterator {
 public:
  typedef typename M::const_iterator StlIterator;
  typedef typename M::value_type PairType;
  typedef typename PairType::second_type ValueType;

  MapIterator(const M &m, StlIterator iter)
      : map_(m), begin_(iter), iter_(iter) {}

  bool Done() const {
    return iter_ == map_.end() || iter_->first != begin_->first;
  }

  ValueType Value() const { return iter_->second; }
  void Next() { ++iter_; }
  void Reset() { iter_ = begin_; }

 private:
  const M &map_;
  StlIterator begin_;
  StlIterator iter_;
};

//
// PdtParenReachable: Provides various parenthesis reachability information
// on a PDT.
//

template <class A>
class PdtParenReachable {
 public:
  typedef typename A::StateId StateId;
  typedef typename A::Label Label;
 public:
  // Maps from state ID to reachable paren IDs from (to) that state.
  typedef unordered_multimap<StateId, Label> ParenMultiMap;

  // Maps from paren ID and state ID to reachable state set ID
  typedef unordered_map<ParenState<A>, ssize_t,
                   typename ParenState<A>::Hash> StateSetMap;

  // Maps from paren ID and state ID to arcs exiting that state with that
  // Label.
  typedef unordered_multimap<ParenState<A>, A,
                        typename ParenState<A>::Hash> ParenArcMultiMap;

  typedef MapIterator<ParenMultiMap> ParenIterator;

  typedef MapIterator<ParenArcMultiMap> ParenArcIterator;

  typedef typename Collection<ssize_t, StateId>::SetIterator SetIterator;

  // Computes close (open) parenthesis reachabilty information for
  // a PDT with bounded stack.
  PdtParenReachable(const Fst<A> &fst,
                    const vector<pair<Label, Label> > &parens, bool close)
      : fst_(fst),
        parens_(parens),
        close_(close),
        error_(false) {
    for (Label i = 0; i < parens.size(); ++i) {
      const pair<Label, Label>  &p = parens[i];
      paren_id_map_[p.first] = i;
      paren_id_map_[p.second] = i;
    }

    if (close_) {
      StateId start = fst.Start();
      if (start == kNoStateId)
        return;
      if (!DFSearch(start)) {
        FSTERROR() << "PdtReachable: Underlying cyclicity not supported";
        error_ = true;
      }
    } else {
      FSTERROR() << "PdtParenReachable: open paren info not implemented";
      error_ = true;
    }
  }

  bool const Error() { return error_; }

  // Given a state ID, returns an iterator over paren IDs
  // for close (open) parens reachable from that state along balanced
  // paths.
  ParenIterator FindParens(StateId s) const {
    return ParenIterator(paren_multimap_, paren_multimap_.find(s));
  }

  // Given a paren ID and a state ID s, returns an iterator over
  // states that can be reached along balanced paths from (to) s that
  // have have close (open) parentheses matching the paren ID exiting
  // (entering) those states.
  SetIterator FindStates(Label paren_id, StateId s) const {
    ParenState<A> paren_state(paren_id, s);
    typename StateSetMap::const_iterator id_it = set_map_.find(paren_state);
    if (id_it == set_map_.end()) {
      return state_sets_.FindSet(-1);
    } else {
      return state_sets_.FindSet(id_it->second);
    }
  }

  // Given a paren Id and a state ID s, return an iterator over
  // arcs that exit (enter) s and are labeled with a close (open)
  // parenthesis matching the paren ID.
  ParenArcIterator FindParenArcs(Label paren_id, StateId s) const {
    ParenState<A> paren_state(paren_id, s);
    return ParenArcIterator(paren_arc_multimap_,
                            paren_arc_multimap_.find(paren_state));
  }

 private:
  // DFS that gathers paren and state set information.
  // Bool returns false when cycle detected.
  bool DFSearch(StateId s);

  // Unions state sets together gathered by the DFS.
  void ComputeStateSet(StateId s);

  // Gather state set(s) from state 'nexts'.
  void UpdateStateSet(StateId nexts, set<Label> *paren_set,
                      vector< set<StateId> > *state_sets) const;

  const Fst<A> &fst_;
  const vector<pair<Label, Label> > &parens_;         // Paren ID -> Labels
  bool close_;                                        // Close/open paren info?
  unordered_map<Label, Label> paren_id_map_;               // Paren labels -> ID
  ParenMultiMap paren_multimap_;                      // Paren reachability
  ParenArcMultiMap paren_arc_multimap_;               // Paren Arcs
  vector<char> state_color_;                          // DFS state
  mutable Collection<ssize_t, StateId> state_sets_;   // Reachable states -> ID
  StateSetMap set_map_;                               // ID -> Reachable states
  bool error_;
  DISALLOW_COPY_AND_ASSIGN(PdtParenReachable);
};

// DFS that gathers paren and state set information.
template <class A>
bool PdtParenReachable<A>::DFSearch(StateId s) {
  if (s >= state_color_.size())
    state_color_.resize(s + 1, kDfsWhite);

  if (state_color_[s] == kDfsBlack)
    return true;

  if (state_color_[s] == kDfsGrey)
    return false;

  state_color_[s] = kDfsGrey;

  for (ArcIterator<Fst<A> > aiter(fst_, s);
       !aiter.Done();
       aiter.Next()) {
    const A &arc = aiter.Value();

    typename unordered_map<Label, Label>::const_iterator pit
        = paren_id_map_.find(arc.ilabel);
    if (pit != paren_id_map_.end()) {               // paren?
      Label paren_id = pit->second;
      if (arc.ilabel == parens_[paren_id].first) {  // open paren
        if (!DFSearch(arc.nextstate))
          return false;
        for (SetIterator set_iter = FindStates(paren_id, arc.nextstate);
             !set_iter.Done(); set_iter.Next()) {
          for (ParenArcIterator paren_arc_iter =
                   FindParenArcs(paren_id, set_iter.Element());
               !paren_arc_iter.Done();
               paren_arc_iter.Next()) {
            const A &cparc = paren_arc_iter.Value();
            if (!DFSearch(cparc.nextstate))
              return false;
          }
        }
      }
    } else {                                       // non-paren
      if(!DFSearch(arc.nextstate))
        return false;
    }
  }
  ComputeStateSet(s);
  state_color_[s] = kDfsBlack;
  return true;
}

// Unions state sets together gathered by the DFS.
template <class A>
void PdtParenReachable<A>::ComputeStateSet(StateId s) {
  set<Label> paren_set;
  vector< set<StateId> > state_sets(parens_.size());
  for (ArcIterator< Fst<A> > aiter(fst_, s);
       !aiter.Done();
       aiter.Next()) {
    const A &arc = aiter.Value();

    typename unordered_map<Label, Label>::const_iterator pit
        = paren_id_map_.find(arc.ilabel);
    if (pit != paren_id_map_.end()) {               // paren?
      Label paren_id = pit->second;
      if (arc.ilabel == parens_[paren_id].first) {  // open paren
        for (SetIterator set_iter =
                 FindStates(paren_id, arc.nextstate);
             !set_iter.Done(); set_iter.Next()) {
          for (ParenArcIterator paren_arc_iter =
                   FindParenArcs(paren_id, set_iter.Element());
               !paren_arc_iter.Done();
               paren_arc_iter.Next()) {
            const A &cparc = paren_arc_iter.Value();
            UpdateStateSet(cparc.nextstate, &paren_set, &state_sets);
          }
        }
      } else {                                      // close paren
        paren_set.insert(paren_id);
        state_sets[paren_id].insert(s);
        ParenState<A> paren_state(paren_id, s);
        paren_arc_multimap_.insert(make_pair(paren_state, arc));
      }
    } else {                                        // non-paren
      UpdateStateSet(arc.nextstate, &paren_set, &state_sets);
    }
  }

  vector<StateId> state_set;
  for (typename set<Label>::iterator paren_iter = paren_set.begin();
       paren_iter != paren_set.end(); ++paren_iter) {
    state_set.clear();
    Label paren_id = *paren_iter;
    paren_multimap_.insert(make_pair(s, paren_id));
    for (typename set<StateId>::iterator state_iter
             = state_sets[paren_id].begin();
         state_iter != state_sets[paren_id].end();
         ++state_iter) {
      state_set.push_back(*state_iter);
    }
    ParenState<A> paren_state(paren_id, s);
    set_map_[paren_state] = state_sets_.FindId(state_set);
  }
}

// Gather state set(s) from state 'nexts'.
template <class A>
void PdtParenReachable<A>::UpdateStateSet(
    StateId nexts, set<Label> *paren_set,
    vector< set<StateId> > *state_sets) const {
  for(ParenIterator paren_iter = FindParens(nexts);
      !paren_iter.Done(); paren_iter.Next()) {
    Label paren_id = paren_iter.Value();
    paren_set->insert(paren_id);
    for (SetIterator set_iter = FindStates(paren_id, nexts);
         !set_iter.Done(); set_iter.Next()) {
      (*state_sets)[paren_id].insert(set_iter.Element());
    }
  }
}


// Store balancing parenthesis data for a PDT. Allows on-the-fly
// construction (e.g. in PdtShortestPath) unlike PdtParenReachable above.
template <class A>
class PdtBalanceData {
 public:
  typedef typename A::StateId StateId;
  typedef typename A::Label Label;

  // Hash set for open parens
  typedef unordered_set<ParenState<A>, typename ParenState<A>::Hash> OpenParenSet;

  // Maps from open paren destination state to parenthesis ID.
  typedef unordered_multimap<StateId, Label> OpenParenMap;

  // Maps from open paren state to source states of matching close parens
  typedef unordered_multimap<ParenState<A>, StateId,
                        typename ParenState<A>::Hash> CloseParenMap;

  // Maps from open paren state to close source set ID
  typedef unordered_map<ParenState<A>, ssize_t,
                   typename ParenState<A>::Hash> CloseSourceMap;

  typedef typename Collection<ssize_t, StateId>::SetIterator SetIterator;

  PdtBalanceData() {}

  void Clear() {
    open_paren_map_.clear();
    close_paren_map_.clear();
  }

  // Adds an open parenthesis with destination state 'open_dest'.
  void OpenInsert(Label paren_id, StateId open_dest) {
    ParenState<A> key(paren_id, open_dest);
    if (!open_paren_set_.count(key)) {
      open_paren_set_.insert(key);
      open_paren_map_.insert(make_pair(open_dest, paren_id));
    }
  }

  // Adds a matching closing parenthesis with source state
  // 'close_source' that balances an open_parenthesis with destination
  // state 'open_dest' if OpenInsert() previously called
  // (o.w. CloseInsert() does nothing).
  void CloseInsert(Label paren_id, StateId open_dest, StateId close_source) {
    ParenState<A> key(paren_id, open_dest);
    if (open_paren_set_.count(key))
      close_paren_map_.insert(make_pair(key, close_source));
  }

  // Find close paren source states matching an open parenthesis.
  // Methods that follow, iterate through those matching states.
  // Should be called only after FinishInsert(open_dest).
  SetIterator Find(Label paren_id, StateId open_dest) {
    ParenState<A> close_key(paren_id, open_dest);
    typename CloseSourceMap::const_iterator id_it =
        close_source_map_.find(close_key);
    if (id_it == close_source_map_.end()) {
      return close_source_sets_.FindSet(-1);
    } else {
      return close_source_sets_.FindSet(id_it->second);
    }
  }

  // Call when all open and close parenthesis insertions wrt open
  // parentheses entering 'open_dest' are finished. Must be called
  // before Find(open_dest). Stores close paren source state sets
  // efficiently.
  void FinishInsert(StateId open_dest) {
    vector<StateId> close_sources;
    for (typename OpenParenMap::iterator oit = open_paren_map_.find(open_dest);
         oit != open_paren_map_.end() && oit->first == open_dest;) {
      Label paren_id = oit->second;
      close_sources.clear();
      ParenState<A> okey(paren_id, open_dest);
      open_paren_set_.erase(open_paren_set_.find(okey));
      for (typename CloseParenMap::iterator cit = close_paren_map_.find(okey);
           cit != close_paren_map_.end() && cit->first == okey;) {
        close_sources.push_back(cit->second);
        close_paren_map_.erase(cit++);
      }
      sort(close_sources.begin(), close_sources.end());
      typename vector<StateId>::iterator unique_end =
          unique(close_sources.begin(), close_sources.end());
      close_sources.resize(unique_end - close_sources.begin());

      if (!close_sources.empty())
        close_source_map_[okey] = close_source_sets_.FindId(close_sources);
      open_paren_map_.erase(oit++);
    }
  }

  // Return a new balance data object representing the reversed balance
  // information.
  PdtBalanceData<A> *Reverse(StateId num_states,
                               StateId num_split,
                               StateId state_id_shift) const;

 private:
  OpenParenSet open_paren_set_;                      // open par. at dest?

  OpenParenMap open_paren_map_;                      // open parens per state
  ParenState<A> open_dest_;                          // cur open dest. state
  typename OpenParenMap::const_iterator open_iter_;  // cur open parens/state

  CloseParenMap close_paren_map_;                    // close states/open
                                                     //  paren and state

  CloseSourceMap close_source_map_;                  // paren, state to set ID
  mutable Collection<ssize_t, StateId> close_source_sets_;
};

// Return a new balance data object representing the reversed balance
// information.
template <class A>
PdtBalanceData<A> *PdtBalanceData<A>::Reverse(
    StateId num_states,
    StateId num_split,
    StateId state_id_shift) const {
  PdtBalanceData<A> *bd = new PdtBalanceData<A>;
  unordered_set<StateId> close_sources;
  StateId split_size = num_states / num_split;

  for (StateId i = 0; i < num_states; i+= split_size) {
    close_sources.clear();

    for (typename CloseSourceMap::const_iterator
             sit = close_source_map_.begin();
         sit != close_source_map_.end();
         ++sit) {
      ParenState<A> okey = sit->first;
      StateId open_dest = okey.state_id;
      Label paren_id = okey.paren_id;
      for (SetIterator set_iter = close_source_sets_.FindSet(sit->second);
           !set_iter.Done(); set_iter.Next()) {
        StateId close_source = set_iter.Element();
        if ((close_source < i) || (close_source >= i + split_size))
          continue;
        close_sources.insert(close_source + state_id_shift);
        bd->OpenInsert(paren_id, close_source + state_id_shift);
        bd->CloseInsert(paren_id, close_source + state_id_shift,
                        open_dest + state_id_shift);
      }
    }

    for (typename unordered_set<StateId>::const_iterator it
             = close_sources.begin();
         it != close_sources.end();
         ++it) {
      bd->FinishInsert(*it);
    }

  }
  return bd;
}


}  // namespace fst

#endif  // FST_EXTENSIONS_PDT_PAREN_H_
