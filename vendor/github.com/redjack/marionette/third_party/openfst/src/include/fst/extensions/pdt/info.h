// info.h

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
// Prints information about a PDT.

#ifndef FST_EXTENSIONS_PDT_INFO_H__
#define FST_EXTENSIONS_PDT_INFO_H__

#include <unordered_map>
using std::unordered_map;
using std::unordered_multimap;
#include <unordered_set>
using std::unordered_set;
using std::unordered_multiset;
#include <vector>
using std::vector;

#include <fst/fst.h>
#include <fst/extensions/pdt/pdt.h>

namespace fst {

// Compute various information about PDTs, helper class for pdtinfo.cc.
template <class A> class PdtInfo {
public:
  typedef A Arc;
  typedef typename A::StateId StateId;
  typedef typename A::Label Label;
  typedef typename A::Weight Weight;

  PdtInfo(const Fst<A> &fst,
          const vector<pair<typename A::Label,
          typename A::Label> > &parens);

  const string& FstType() const { return fst_type_; }
  const string& ArcType() const { return A::Type(); }

  int64 NumStates() const { return nstates_; }
  int64 NumArcs() const { return narcs_; }
  int64 NumOpenParens() const { return nopen_parens_; }
  int64 NumCloseParens() const { return nclose_parens_; }
  int64 NumUniqueOpenParens() const { return nuniq_open_parens_; }
  int64 NumUniqueCloseParens() const { return nuniq_close_parens_; }
  int64 NumOpenParenStates() const { return nopen_paren_states_; }
  int64 NumCloseParenStates() const { return nclose_paren_states_; }

 private:
  string fst_type_;
  int64 nstates_;
  int64 narcs_;
  int64 nopen_parens_;
  int64 nclose_parens_;
  int64 nuniq_open_parens_;
  int64 nuniq_close_parens_;
  int64 nopen_paren_states_;
  int64 nclose_paren_states_;

  DISALLOW_COPY_AND_ASSIGN(PdtInfo);
};

template <class A>
PdtInfo<A>::PdtInfo(const Fst<A> &fst,
                 const vector<pair<typename A::Label,
                                   typename A::Label> > &parens)
  : fst_type_(fst.Type()),
    nstates_(0),
    narcs_(0),
    nopen_parens_(0),
    nclose_parens_(0),
    nuniq_open_parens_(0),
    nuniq_close_parens_(0),
    nopen_paren_states_(0),
    nclose_paren_states_(0) {
  unordered_map<Label, size_t> paren_map;
  unordered_set<Label> paren_set;
  unordered_set<StateId> open_paren_state_set;
  unordered_set<StateId> close_paren_state_set;

  for (size_t i = 0; i < parens.size(); ++i) {
    const pair<Label, Label>  &p = parens[i];
    paren_map[p.first] = i;
    paren_map[p.second] = i;
  }

  for (StateIterator< Fst<A> > siter(fst);
       !siter.Done();
       siter.Next()) {
    ++nstates_;
    StateId s = siter.Value();
    for (ArcIterator< Fst<A> > aiter(fst, s);
         !aiter.Done();
         aiter.Next()) {
      const A &arc = aiter.Value();
      ++narcs_;
      typename unordered_map<Label, size_t>::const_iterator pit
        = paren_map.find(arc.ilabel);
      if (pit != paren_map.end()) {
        Label open_paren =  parens[pit->second].first;
        Label close_paren =  parens[pit->second].second;
        if (arc.ilabel == open_paren) {
          ++nopen_parens_;
          if (!paren_set.count(open_paren)) {
            ++nuniq_open_parens_;
            paren_set.insert(open_paren);
          }
          if (!open_paren_state_set.count(arc.nextstate)) {
            ++nopen_paren_states_;
            open_paren_state_set.insert(arc.nextstate);
          }
        } else {
          ++nclose_parens_;
          if (!paren_set.count(close_paren)) {
            ++nuniq_close_parens_;
            paren_set.insert(close_paren);
          }
          if (!close_paren_state_set.count(s)) {
            ++nclose_paren_states_;
            close_paren_state_set.insert(s);
          }

        }
      }
    }
  }
}


template <class A>
void PrintPdtInfo(const PdtInfo<A> &pdtinfo) {
  ios_base::fmtflags old = cout.setf(ios::left);
  cout.width(50);
  cout << "fst type" << pdtinfo.FstType().c_str() << endl;
  cout.width(50);
  cout << "arc type" << pdtinfo.ArcType().c_str() << endl;
  cout.width(50);
  cout << "# of states" << pdtinfo.NumStates() << endl;
  cout.width(50);
  cout << "# of arcs" << pdtinfo.NumArcs() << endl;
  cout.width(50);
  cout << "# of open parentheses" << pdtinfo.NumOpenParens() << endl;
  cout.width(50);
  cout << "# of close parentheses" << pdtinfo.NumCloseParens() << endl;
  cout.width(50);
  cout << "# of unique open parentheses"
       << pdtinfo.NumUniqueOpenParens() << endl;
  cout.width(50);
  cout << "# of unique close parentheses"
       << pdtinfo.NumUniqueCloseParens() << endl;
  cout.width(50);
  cout << "# of open parenthesis dest. states"
       << pdtinfo.NumOpenParenStates() << endl;
  cout.width(50);
  cout << "# of close parenthesis source states"
       << pdtinfo.NumCloseParenStates() << endl;
  cout.setf(old);
}

}  // namespace fst

#endif  // FST_EXTENSIONS_PDT_INFO_H__
