// replace.h

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
// Recursively replace Fst arcs with other Fst(s) returning a PDT.

#ifndef FST_EXTENSIONS_PDT_REPLACE_H__
#define FST_EXTENSIONS_PDT_REPLACE_H__

#include <unordered_map>
using std::unordered_map;
using std::unordered_multimap;

#include <fst/replace.h>

namespace fst {

// Hash to paren IDs
template <typename S>
struct ReplaceParenHash {
  size_t operator()(const pair<size_t, S> &p) const {
    return p.first + p.second * kPrime;
  }
 private:
  static const size_t kPrime = 7853;
};

template <typename S> const size_t ReplaceParenHash<S>::kPrime;

// Builds a pushdown transducer (PDT) from an RTN specification
// identical to that in fst/lib/replace.h. The result is a PDT
// encoded as the FST 'ofst' where some transitions are labeled with
// open or close parentheses. To be interpreted as a PDT, the parens
// must balance on a path (see PdtExpand()). The open/close
// parenthesis label pairs are returned in 'parens'.
template <class Arc>
void Replace(const vector<pair<typename Arc::Label,
             const Fst<Arc>* > >& ifst_array,
             MutableFst<Arc> *ofst,
             vector<pair<typename Arc::Label,
             typename Arc::Label> > *parens,
             typename Arc::Label root) {
  typedef typename Arc::Label Label;
  typedef typename Arc::StateId StateId;
  typedef typename Arc::Weight Weight;

  ofst->DeleteStates();
  parens->clear();

  // Builds map from non-terminal label to FST id.
  unordered_map<Label, size_t> label2id;
  for (size_t i = 0; i < ifst_array.size(); ++i)
    label2id[ifst_array[i].first] = i;

  Label max_label = kNoLabel;

  // Queue of non-terminals to replace
  deque<size_t> non_term_queue;
  non_term_queue.push_back(root);

  // PDT state corr. to ith replace FST start state.
  vector<StateId> fst_start(ifst_array.size(), kNoStateId);
  // PDT state, weight pairs corr. to ith replace FST final state & weights.
  vector< vector<pair<StateId, Weight> > > fst_final(ifst_array.size());

  typedef unordered_map<pair<size_t, StateId>, size_t,
                   ReplaceParenHash<StateId> > ParenMap;
  // Map that gives the paren ID for a (non-terminal, dest. state) pair
  // (which can be unique).
  ParenMap paren_map;
  // # of distinct parenthesis pairs per fst.
  vector<size_t> nparens(ifst_array.size(), 0);
  // # of distinct parenthesis pairs overall.
  size_t total_nparens = 0;

  // Builds single Fst combining all referenced input Fsts. Leaves in the
  // non-termnals for now.  Tabulate the PDT states that correspond to
  // the start and final states of the input Fsts. For each non-terminal
  // assigns an paren ID to each instance starting at 0; they are distinct
  // IDs unless the instances have the same destination state.
  for (StateId soff = 0; !non_term_queue.empty(); soff = ofst->NumStates()) {
    Label label = non_term_queue.front();
    non_term_queue.pop_front();
    size_t fst_id = label2id[label];

    const Fst<Arc> *ifst = ifst_array[fst_id].second;
    for (StateIterator< Fst<Arc> > siter(*ifst);
         !siter.Done(); siter.Next()) {
      StateId is = siter.Value();
      StateId os = ofst->AddState();
      if (is == ifst->Start()) {
        fst_start[fst_id] = os;
        if (label == root)
          ofst->SetStart(os);
      }
      if (ifst->Final(is) != Weight::Zero()) {
        if (label == root)
          ofst->SetFinal(os, ifst->Final(is));
        fst_final[fst_id].push_back(make_pair(os, ifst->Final(is)));
      }
      for (ArcIterator< Fst<Arc> > aiter(*ifst, is);
           !aiter.Done(); aiter.Next()) {
        Arc arc = aiter.Value();
        arc.nextstate += soff;
        if (max_label == kNoLabel || arc.olabel > max_label)
          max_label = arc.olabel;
        typename unordered_map<Label, size_t>::const_iterator it =
            label2id.find(arc.olabel);
        if (it != label2id.end()) {
          size_t nfst_id = it->second;
          if (ifst_array[nfst_id].second->Start() == kNoStateId)
            continue;
          if (arc.olabel != root && nparens[nfst_id] == 0)
            non_term_queue.push_back(arc.olabel);
          pair<size_t, StateId> paren_key(nfst_id, arc.nextstate);
          typename ParenMap::const_iterator pit = paren_map.find(paren_key);
          if (pit == paren_map.end()) {
            paren_map[paren_key] = nparens[nfst_id]++;
            if (nparens[nfst_id] > total_nparens)
              total_nparens = nparens[nfst_id];
          }
        }
        ofst->AddArc(os, arc);
      }
    }
  }

  // Assigns parenthesis labels
  for (size_t paren_id = 0; paren_id < total_nparens; ++paren_id) {
    Label open_paren = max_label + paren_id + 1;
    Label close_paren = open_paren + total_nparens;
    parens->push_back(make_pair(open_paren, close_paren));
  }

  // Changes each non-terminal transition to an open parenthesis
  // transition redirected to the PDT state that corresponds to the
  // start state of the input FST for the non-terminal. Adds close parenthesis
  // transitions from the PDT states corr. to the final states of the
  // input FST for the non-terminal to the former destination state of the
  // non-terminal transition.
  typedef MutableArcIterator< MutableFst<Arc> > MIter;
  for (StateIterator< Fst<Arc> > siter(*ofst);
       !siter.Done(); siter.Next()) {
    StateId os = siter.Value();
    MIter *aiter = new MIter(ofst, os);
    for (size_t n = 0; !aiter->Done(); aiter->Next(), ++n) {
      Arc arc = aiter->Value();
      typename unordered_map<Label, size_t>::const_iterator lit =
          label2id.find(arc.olabel);
      if (lit != label2id.end()) {
        size_t nfst_id = lit->second;

        // Get parentheses.
        pair<size_t, StateId> paren_key(nfst_id, arc.nextstate);
        typename ParenMap::const_iterator pit = paren_map.find(paren_key);
        size_t paren_id = pit->second;
        Label open_paren = (*parens)[paren_id].first;
        Label close_paren = (*parens)[paren_id].second;

        // Sets open parenthesis.
        Arc sarc(open_paren, open_paren, arc.weight, fst_start[nfst_id]);
        aiter->SetValue(sarc);

        // Adds close parentheses.
        for (size_t i = 0; i < fst_final[nfst_id].size(); ++i) {
          pair<StateId, Weight> &p = fst_final[nfst_id][i];
          Arc farc(close_paren, close_paren, p.second, arc.nextstate);

          ofst->AddArc(p.first, farc);
          if (os == p.first) {  // Invalidated iterator
            delete aiter;
            aiter = new MIter(ofst, os);
            aiter->Seek(n);
          }
        }
      }
    }
    delete aiter;
  }
}

}  // namespace fst

#endif  // FST_EXTENSIONS_PDT_REPLACE_H__
