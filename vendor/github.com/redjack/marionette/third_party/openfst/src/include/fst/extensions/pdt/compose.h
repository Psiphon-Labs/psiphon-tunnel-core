// compose.h

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
// Compose a PDT and an FST.

#ifndef FST_EXTENSIONS_PDT_COMPOSE_H__
#define FST_EXTENSIONS_PDT_COMPOSE_H__

#include <list>

#include <fst/extensions/pdt/pdt.h>
#include <fst/compose.h>

namespace fst {

// Return paren arcs for Find(kNoLabel).
const uint32 kParenList =  0x00000001;

// Return a kNolabel loop for Find(paren).
const uint32 kParenLoop =  0x00000002;

// This class is a matcher that treats parens as multi-epsilon labels.
// It is most efficient if the parens are in a range non-overlapping with
// the non-paren labels.
template <class F>
class ParenMatcher {
 public:
  typedef SortedMatcher<F> M;
  typedef typename M::FST FST;
  typedef typename M::Arc Arc;
  typedef typename Arc::StateId StateId;
  typedef typename Arc::Label Label;
  typedef typename Arc::Weight Weight;

  ParenMatcher(const FST &fst, MatchType match_type,
               uint32 flags = (kParenLoop | kParenList))
      : matcher_(fst, match_type),
        match_type_(match_type),
        flags_(flags) {
    if (match_type == MATCH_INPUT) {
      loop_.ilabel = kNoLabel;
      loop_.olabel = 0;
    } else {
      loop_.ilabel = 0;
      loop_.olabel = kNoLabel;
    }
    loop_.weight = Weight::One();
    loop_.nextstate = kNoStateId;
  }

  ParenMatcher(const ParenMatcher<F> &matcher, bool safe = false)
      : matcher_(matcher.matcher_, safe),
        match_type_(matcher.match_type_),
        flags_(matcher.flags_),
        open_parens_(matcher.open_parens_),
        close_parens_(matcher.close_parens_),
        loop_(matcher.loop_) {
    loop_.nextstate = kNoStateId;
  }

  ParenMatcher<F> *Copy(bool safe = false) const {
    return new ParenMatcher<F>(*this, safe);
  }

  MatchType Type(bool test) const { return matcher_.Type(test); }

  void SetState(StateId s) {
    matcher_.SetState(s);
    loop_.nextstate = s;
  }

  bool Find(Label match_label);

  bool Done() const {
    return done_;
  }

  const Arc& Value() const {
    return paren_loop_ ? loop_ : matcher_.Value();
  }

  void Next();

  ssize_t Priority(StateId s) { return matcher_.Priority(s); }

  const FST &GetFst() const { return matcher_.GetFst(); }

  uint64 Properties(uint64 props) const { return matcher_.Properties(props); }

  uint32 Flags() const { return matcher_.Flags(); }

  void AddOpenParen(Label label) {
    if (label == 0) {
      FSTERROR() << "ParenMatcher: Bad open paren label: 0";
    } else {
      open_parens_.Insert(label);
    }
  }

  void AddCloseParen(Label label) {
    if (label == 0) {
      FSTERROR() << "ParenMatcher: Bad close paren label: 0";
    } else {
      close_parens_.Insert(label);
    }
  }

  void RemoveOpenParen(Label label) {
    if (label == 0) {
      FSTERROR() << "ParenMatcher: Bad open paren label: 0";
    } else {
      open_parens_.Erase(label);
    }
  }

  void RemoveCloseParen(Label label) {
    if (label == 0) {
      FSTERROR() << "ParenMatcher: Bad close paren label: 0";
    } else {
      close_parens_.Erase(label);
    }
  }

  void ClearOpenParens() {
    open_parens_.Clear();
  }

  void ClearCloseParens() {
    close_parens_.Clear();
  }

  bool IsOpenParen(Label label) const {
    return open_parens_.Member(label);
  }

  bool IsCloseParen(Label label) const {
    return close_parens_.Member(label);
  }

 private:
  // Advances matcher to next open paren if it exists, returning true.
  // O.w. returns false.
  bool NextOpenParen();

  // Advances matcher to next open paren if it exists, returning true.
  // O.w. returns false.
  bool NextCloseParen();

  M matcher_;
  MatchType match_type_;          // Type of match to perform
  uint32 flags_;

  // open paren label set
  CompactSet<Label, kNoLabel> open_parens_;

  // close paren label set
  CompactSet<Label, kNoLabel> close_parens_;


  bool open_paren_list_;         // Matching open paren list
  bool close_paren_list_;        // Matching close paren list
  bool paren_loop_;              // Current arc is the implicit paren loop
  mutable Arc loop_;             // For non-consuming symbols
  bool done_;                    // Matching done

  void operator=(const ParenMatcher<F> &);  // Disallow
};

template <class M> inline
bool ParenMatcher<M>::Find(Label match_label) {
  open_paren_list_ = false;
  close_paren_list_ = false;
  paren_loop_ = false;
  done_ = false;

  // Returns all parenthesis arcs
  if (match_label == kNoLabel && (flags_ & kParenList)) {
    if (open_parens_.LowerBound() != kNoLabel) {
      matcher_.LowerBound(open_parens_.LowerBound());
      open_paren_list_ = NextOpenParen();
      if (open_paren_list_) return true;
    }
    if (close_parens_.LowerBound() != kNoLabel) {
      matcher_.LowerBound(close_parens_.LowerBound());
      close_paren_list_ = NextCloseParen();
      if (close_paren_list_) return true;
    }
  }

  // Returns 'implicit' paren loop
  if (match_label > 0 && (flags_ & kParenLoop) &&
      (IsOpenParen(match_label) || IsCloseParen(match_label))) {
    paren_loop_ = true;
    return true;
  }

  // Returns all other labels
  if (matcher_.Find(match_label))
    return true;

  done_ = true;
  return false;
}

template <class F> inline
void ParenMatcher<F>::Next() {
  if (paren_loop_) {
    paren_loop_ = false;
    done_ = true;
  } else if (open_paren_list_) {
    matcher_.Next();
    open_paren_list_ = NextOpenParen();
    if (open_paren_list_) return;

    if (close_parens_.LowerBound() != kNoLabel) {
      matcher_.LowerBound(close_parens_.LowerBound());
      close_paren_list_ = NextCloseParen();
      if (close_paren_list_) return;
    }
    done_ = !matcher_.Find(kNoLabel);
  } else if (close_paren_list_) {
    matcher_.Next();
    close_paren_list_ = NextCloseParen();
    if (close_paren_list_) return;
    done_ = !matcher_.Find(kNoLabel);
  } else {
    matcher_.Next();
    done_ = matcher_.Done();
  }
}

// Advances matcher to next open paren if it exists, returning true.
// O.w. returns false.
template <class F> inline
bool ParenMatcher<F>::NextOpenParen() {
  for (; !matcher_.Done(); matcher_.Next()) {
    Label label = match_type_ == MATCH_INPUT ?
        matcher_.Value().ilabel : matcher_.Value().olabel;
    if (label > open_parens_.UpperBound())
      return false;
    if (IsOpenParen(label))
      return true;
  }
  return false;
}

// Advances matcher to next close paren if it exists, returning true.
// O.w. returns false.
template <class F> inline
bool ParenMatcher<F>::NextCloseParen() {
  for (; !matcher_.Done(); matcher_.Next()) {
    Label label = match_type_ == MATCH_INPUT ?
        matcher_.Value().ilabel : matcher_.Value().olabel;
    if (label > close_parens_.UpperBound())
      return false;
    if (IsCloseParen(label))
      return true;
  }
  return false;
}


template <class F>
class ParenFilter {
 public:
  typedef typename F::FST1 FST1;
  typedef typename F::FST2 FST2;
  typedef typename F::Arc Arc;
  typedef typename Arc::StateId StateId;
  typedef typename Arc::Label Label;
  typedef typename Arc::Weight Weight;
  typedef typename F::Matcher1 Matcher1;
  typedef typename F::Matcher2 Matcher2;
  typedef typename F::FilterState FilterState1;
  typedef StateId StackId;
  typedef PdtStack<StackId, Label> ParenStack;
  typedef IntegerFilterState<StackId> FilterState2;
  typedef PairFilterState<FilterState1, FilterState2> FilterState;
  typedef ParenFilter<F> Filter;

  ParenFilter(const FST1 &fst1, const FST2 &fst2,
              Matcher1 *matcher1 = 0,  Matcher2 *matcher2 = 0,
              const vector<pair<Label, Label> > *parens = 0,
              bool expand = false, bool keep_parens = true)
      : filter_(fst1, fst2, matcher1, matcher2),
        parens_(parens ? *parens : vector<pair<Label, Label> >()),
        expand_(expand),
        keep_parens_(keep_parens),
        f_(FilterState::NoState()),
        stack_(parens_),
        paren_id_(-1) {
    if (parens) {
      for (size_t i = 0; i < parens->size(); ++i) {
        const pair<Label, Label>  &p = (*parens)[i];
        parens_.push_back(p);
        GetMatcher1()->AddOpenParen(p.first);
        GetMatcher2()->AddOpenParen(p.first);
        if (!expand_) {
          GetMatcher1()->AddCloseParen(p.second);
          GetMatcher2()->AddCloseParen(p.second);
        }
      }
    }
  }

  ParenFilter(const Filter &filter, bool safe = false)
      : filter_(filter.filter_, safe),
        parens_(filter.parens_),
        expand_(filter.expand_),
        keep_parens_(filter.keep_parens_),
        f_(FilterState::NoState()),
        stack_(filter.parens_),
        paren_id_(-1) { }

  FilterState Start() const {
    return FilterState(filter_.Start(), FilterState2(0));
  }

  void SetState(StateId s1, StateId s2, const FilterState &f) {
    f_ = f;
    filter_.SetState(s1, s2, f_.GetState1());
    if (!expand_)
      return;

    ssize_t paren_id = stack_.Top(f.GetState2().GetState());
    if (paren_id != paren_id_) {
      if (paren_id_ != -1) {
        GetMatcher1()->RemoveCloseParen(parens_[paren_id_].second);
        GetMatcher2()->RemoveCloseParen(parens_[paren_id_].second);
      }
      paren_id_ = paren_id;
      if (paren_id_ != -1) {
        GetMatcher1()->AddCloseParen(parens_[paren_id_].second);
        GetMatcher2()->AddCloseParen(parens_[paren_id_].second);
      }
    }
  }

  FilterState FilterArc(Arc *arc1, Arc *arc2) const {
    FilterState1 f1 = filter_.FilterArc(arc1, arc2);
    const FilterState2 &f2 = f_.GetState2();
    if (f1 == FilterState1::NoState())
      return FilterState::NoState();

    if (arc1->olabel == kNoLabel && arc2->ilabel) {         // arc2 parentheses
      if (keep_parens_) {
        arc1->ilabel = arc2->ilabel;
      } else if (arc2->ilabel) {
        arc2->olabel = arc1->ilabel;
      }
      return FilterParen(arc2->ilabel, f1, f2);
    } else if (arc2->ilabel == kNoLabel && arc1->olabel) {  // arc1 parentheses
      if (keep_parens_) {
        arc2->olabel = arc1->olabel;
      } else {
        arc1->ilabel = arc2->olabel;
      }
      return FilterParen(arc1->olabel, f1, f2);
    } else {
      return FilterState(f1, f2);
    }
  }

  void FilterFinal(Weight *w1, Weight *w2) const {
    if (f_.GetState2().GetState() != 0)
      *w1 = Weight::Zero();
    filter_.FilterFinal(w1, w2);
  }

  // Return resp matchers. Ownership stays with filter.
  Matcher1 *GetMatcher1() { return filter_.GetMatcher1(); }
  Matcher2 *GetMatcher2() { return filter_.GetMatcher2(); }

  uint64 Properties(uint64 iprops) const {
    uint64 oprops = filter_.Properties(iprops);
    return oprops & kILabelInvariantProperties & kOLabelInvariantProperties;
  }

 private:
  const FilterState FilterParen(Label label, const FilterState1 &f1,
                                const FilterState2 &f2) const {
    if (!expand_)
      return FilterState(f1, f2);

    StackId stack_id = stack_.Find(f2.GetState(), label);
    if (stack_id < 0) {
      return FilterState::NoState();
    } else {
      return FilterState(f1, FilterState2(stack_id));
    }
  }

  F filter_;
  vector<pair<Label, Label> > parens_;
  bool expand_;                    // Expands to FST
  bool keep_parens_;               // Retains parentheses in output
  FilterState f_;                  // Current filter state
  mutable ParenStack stack_;
  ssize_t paren_id_;
};

// Class to setup composition options for PDT composition.
// Default is for the PDT as the first composition argument.
template <class Arc, bool left_pdt = true>
class PdtComposeFstOptions : public
ComposeFstOptions<Arc,
                  ParenMatcher< Fst<Arc> >,
                  ParenFilter<AltSequenceComposeFilter<
                                ParenMatcher< Fst<Arc> > > > > {
 public:
  typedef typename Arc::Label Label;
  typedef ParenMatcher< Fst<Arc> > PdtMatcher;
  typedef ParenFilter<AltSequenceComposeFilter<PdtMatcher> > PdtFilter;
  typedef ComposeFstOptions<Arc, PdtMatcher, PdtFilter> COptions;
  using COptions::matcher1;
  using COptions::matcher2;
  using COptions::filter;

  PdtComposeFstOptions(const Fst<Arc> &ifst1,
                    const vector<pair<Label, Label> > &parens,
                       const Fst<Arc> &ifst2, bool expand = false,
                       bool keep_parens = true) {
    matcher1 = new PdtMatcher(ifst1, MATCH_OUTPUT, kParenList);
    matcher2 = new PdtMatcher(ifst2, MATCH_INPUT, kParenLoop);

    filter = new PdtFilter(ifst1, ifst2, matcher1, matcher2, &parens,
                           expand, keep_parens);
  }
};

// Class to setup composition options for PDT with FST composition.
// Specialization is for the FST as the first composition argument.
template <class Arc>
class PdtComposeFstOptions<Arc, false> : public
ComposeFstOptions<Arc,
                  ParenMatcher< Fst<Arc> >,
                  ParenFilter<SequenceComposeFilter<
                                ParenMatcher< Fst<Arc> > > > > {
 public:
  typedef typename Arc::Label Label;
  typedef ParenMatcher< Fst<Arc> > PdtMatcher;
  typedef ParenFilter<SequenceComposeFilter<PdtMatcher> > PdtFilter;
  typedef ComposeFstOptions<Arc, PdtMatcher, PdtFilter> COptions;
  using COptions::matcher1;
  using COptions::matcher2;
  using COptions::filter;

  PdtComposeFstOptions(const Fst<Arc> &ifst1,
                       const Fst<Arc> &ifst2,
                       const vector<pair<Label, Label> > &parens,
                       bool expand = false, bool keep_parens = true) {
    matcher1 = new PdtMatcher(ifst1, MATCH_OUTPUT, kParenLoop);
    matcher2 = new PdtMatcher(ifst2, MATCH_INPUT, kParenList);

    filter = new PdtFilter(ifst1, ifst2, matcher1, matcher2, &parens,
                           expand, keep_parens);
  }
};

enum PdtComposeFilter {
  PAREN_FILTER,          // Bar-Hillel construction; keeps parentheses
  EXPAND_FILTER,         // Bar-Hillel + expansion; removes parentheses
  EXPAND_PAREN_FILTER,   // Bar-Hillel + expansion; keeps parentheses
};

struct PdtComposeOptions {
  bool connect;  // Connect output
  PdtComposeFilter filter_type;  // Which pre-defined filter to use

  explicit PdtComposeOptions(bool c, PdtComposeFilter ft = PAREN_FILTER)
      : connect(c), filter_type(ft) {}
  PdtComposeOptions() : connect(true), filter_type(PAREN_FILTER) {}
};

// Composes pushdown transducer (PDT) encoded as an FST (1st arg) and
// an FST (2nd arg) with the result also a PDT encoded as an Fst. (3rd arg).
// In the PDTs, some transitions are labeled with open or close
// parentheses. To be interpreted as a PDT, the parens must balance on
// a path (see PdtExpand()). The open-close parenthesis label pairs
// are passed in 'parens'.
template <class Arc>
void Compose(const Fst<Arc> &ifst1,
             const vector<pair<typename Arc::Label,
                               typename Arc::Label> > &parens,
             const Fst<Arc> &ifst2,
             MutableFst<Arc> *ofst,
             const PdtComposeOptions &opts = PdtComposeOptions()) {
  bool expand = opts.filter_type != PAREN_FILTER;
  bool keep_parens = opts.filter_type != EXPAND_FILTER;
  PdtComposeFstOptions<Arc, true> copts(ifst1, parens, ifst2,
                                        expand, keep_parens);
  copts.gc_limit = 0;
  *ofst = ComposeFst<Arc>(ifst1, ifst2, copts);
  if (opts.connect)
    Connect(ofst);
}

// Composes an FST (1st arg) and pushdown transducer (PDT) encoded as
// an FST (2nd arg) with the result also a PDT encoded as an Fst (3rd arg).
// In the PDTs, some transitions are labeled with open or close
// parentheses. To be interpreted as a PDT, the parens must balance on
// a path (see ExpandFst()). The open-close parenthesis label pairs
// are passed in 'parens'.
template <class Arc>
void Compose(const Fst<Arc> &ifst1,
             const Fst<Arc> &ifst2,
             const vector<pair<typename Arc::Label,
                               typename Arc::Label> > &parens,
             MutableFst<Arc> *ofst,
             const PdtComposeOptions &opts = PdtComposeOptions()) {
  bool expand = opts.filter_type != PAREN_FILTER;
  bool keep_parens = opts.filter_type != EXPAND_FILTER;
  PdtComposeFstOptions<Arc, false> copts(ifst1, ifst2, parens,
                                         expand, keep_parens);
  copts.gc_limit = 0;
  *ofst = ComposeFst<Arc>(ifst1, ifst2, copts);
  if (opts.connect)
    Connect(ofst);
}

}  // namespace fst

#endif  // FST_EXTENSIONS_PDT_COMPOSE_H__
