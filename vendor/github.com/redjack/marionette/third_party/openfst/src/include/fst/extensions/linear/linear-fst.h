
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
// Author: riley, wuke
//
// Classes for building, storing and representing log-linear models as FST

#ifndef FST_EXTENSIONS_LINEAR_LINEAR_FST_H_
#define FST_EXTENSIONS_LINEAR_LINEAR_FST_H_

#include <algorithm>
#include <vector>
using std::vector;

#include <fst/compat.h>
#include <fst/extensions/pdt/collection.h>
#include <fst/bi-table.h>
#include <fst/cache.h>
#include <fst/fst.h>
#include <fst/matcher.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <fst/symbol-table.h>

#include <fst/extensions/linear/linear-fst-data.h>

namespace fst {

// Forward declaration of the specialized matcher for both
// LinearTaggerFst and LinearClassifierFst.
template <class F>
class LinearFstMatcherTpl;

// Implementation class for on-the-fly generated LinearTaggerFst with
// special optimization in matching.
template <class A>
class LinearTaggerFstImpl : public CacheImpl<A> {
 public:
  using FstImpl<A>::SetType;
  using FstImpl<A>::SetProperties;
  using FstImpl<A>::SetInputSymbols;
  using FstImpl<A>::SetOutputSymbols;
  using FstImpl<A>::WriteHeader;

  using CacheBaseImpl<CacheState<A> >::PushArc;
  using CacheBaseImpl<CacheState<A> >::HasArcs;
  using CacheBaseImpl<CacheState<A> >::HasFinal;
  using CacheBaseImpl<CacheState<A> >::HasStart;
  using CacheBaseImpl<CacheState<A> >::SetArcs;
  using CacheBaseImpl<CacheState<A> >::SetFinal;
  using CacheBaseImpl<CacheState<A> >::SetStart;

  typedef A Arc;
  typedef typename A::Label Label;
  typedef typename A::Weight Weight;
  typedef typename A::StateId StateId;
  typedef typename Collection<StateId, Label>::SetIterator NGramIterator;

  // Constructs an empty FST by default.
  LinearTaggerFstImpl() : CacheImpl<A>(CacheOptions()), delay_(0) {
    SetType("linear-tagger");
    data_ = new LinearFstData<A>;
  }

  // Constructs the FST with given data storage and symbol
  // tables. When `owner` is true, takes over the ownership of `data`.
  //
  // TODO(wuke): when there is no constraint on output we can delay
  // less than `data->MaxFutureSize` positions.
  LinearTaggerFstImpl(const LinearFstData<Arc> *data, SymbolTable *isyms,
                      SymbolTable *osyms, bool owner, CacheOptions opts)
      : CacheImpl<A>(opts), data_(data), delay_(data->MaxFutureSize()) {
    SetType("linear-tagger");
    SetProperties(kILabelSorted, kFstProperties);
    if (!owner) data_->IncrRefCount();
    SetInputSymbols(isyms);
    SetOutputSymbols(osyms);
    ReserveStubSpace();
  }

  // Copy by sharing the underlying data storage.
  LinearTaggerFstImpl(const LinearTaggerFstImpl &impl)
      : CacheImpl<A>(impl), data_(impl.data_), delay_(impl.delay_) {
    SetType("linear-tagger");
    SetProperties(impl.Properties(), kCopyProperties);
    SetInputSymbols(impl.InputSymbols());
    SetOutputSymbols(impl.OutputSymbols());
    data_->IncrRefCount();
    ReserveStubSpace();
  }

  ~LinearTaggerFstImpl() {
    if (data_->DecrRefCount() == 0) delete data_;
  }

  StateId Start() {
    if (!HasStart()) {
      StateId start = FindStartState();
      SetStart(start);
    }
    return CacheImpl<A>::Start();
  }

  Weight Final(StateId s) {
    if (!HasFinal(s)) {
      state_stub_.clear();
      FillState(s, &state_stub_);
      if (CanBeFinal(state_stub_))
        SetFinal(s, data_->FinalWeight(InternalBegin(state_stub_),
                                       InternalEnd(state_stub_)));
      else
        SetFinal(s, Weight::Zero());
    }
    return CacheImpl<A>::Final(s);
  }

  size_t NumArcs(StateId s) {
    if (!HasArcs(s)) Expand(s);
    return CacheImpl<A>::NumArcs(s);
  }

  size_t NumInputEpsilons(StateId s) {
    if (!HasArcs(s)) Expand(s);
    return CacheImpl<A>::NumInputEpsilons(s);
  }

  size_t NumOutputEpsilons(StateId s) {
    if (!HasArcs(s)) Expand(s);
    return CacheImpl<A>::NumOutputEpsilons(s);
  }

  void InitArcIterator(StateId s, ArcIteratorData<A> *data) {
    if (!HasArcs(s)) Expand(s);
    CacheImpl<A>::InitArcIterator(s, data);
  }

  // Computes the outgoing transitions from a state, creating new
  // destination states as needed.
  void Expand(StateId s);

  // Appends to `arcs` all out-going arcs from state `s` that matches `label` as
  // the input label.
  void MatchInput(StateId s, Label ilabel, vector<Arc> *arcs);

  static LinearTaggerFstImpl<A> *Read(istream &strm,  // NOLINT
                                      const FstReadOptions &opts);

  bool Write(ostream &strm,  // NOLINT
             const FstWriteOptions &opts) const {
    FstHeader header;
    header.SetStart(kNoStateId);
    WriteHeader(strm, opts, kFileVersion, &header);
    data_->Write(strm);
    if (!strm) {
      LOG(ERROR) << "LinearTaggerFst::Write: write failed: " << opts.source;
      return false;
    }
    return true;
  }

 private:
  static const int kMinFileVersion;
  static const int kFileVersion;

  // A collection of functions to access parts of the state tuple. A
  // state tuple is a vector of `Label`s with two parts:
  //   [buffer] [internal].
  //
  // - [buffer] is a buffer of observed input labels with length
  // `delay_`. `LinearFstData<A>::kStartOfSentence`
  // (resp. `LinearFstData<A>::kEndOfSentence`) are used as
  // paddings when the buffer has fewer than `delay_` elements, which
  // can only appear as the prefix (resp. suffix) of the buffer.
  //
  // - [internal] is the internal state tuple for `LinearFstData`
  typename vector<Label>::const_iterator BufferBegin(
      const vector<Label> &state) const {
    return state.begin();
  }

  typename vector<Label>::const_iterator BufferEnd(
      const vector<Label> &state) const {
    return state.begin() + delay_;
  }

  typename vector<Label>::const_iterator InternalBegin(
      const vector<Label> &state) const {
    return state.begin() + delay_;
  }

  typename vector<Label>::const_iterator InternalEnd(
      const vector<Label> &state) const {
    return state.end();
  }

  // The size of state tuples are fixed, reserve them in stubs
  void ReserveStubSpace() {
    state_stub_.reserve(delay_ + data_->NumGroups());
    next_stub_.reserve(delay_ + data_->NumGroups());
  }

  // Computes the start state tuple and maps it to the start state id.
  StateId FindStartState() {
    // Empty buffer with start-of-sentence paddings
    state_stub_.clear();
    state_stub_.resize(delay_, LinearFstData<A>::kStartOfSentence);
    // Append internal states
    data_->EncodeStartState(&state_stub_);
    return FindState(state_stub_);
  }

  // Tests whether the buffer in `(begin, end)` is empty.
  bool IsEmptyBuffer(typename vector<Label>::const_iterator begin,
                     typename vector<Label>::const_iterator end) const {
    // The following is guanranteed by `ShiftBuffer()`:
    // - buffer[i] == LinearFstData<A>::kEndOfSentence =>
    //       buffer[i+x] == LinearFstData<A>::kEndOfSentence
    // - buffer[i] == LinearFstData<A>::kStartOfSentence =>
    //       buffer[i-x] == LinearFstData<A>::kStartOfSentence
    return delay_ == 0 || *(end - 1) == LinearFstData<A>::kStartOfSentence ||
           *begin == LinearFstData<A>::kEndOfSentence;
  }

  // Tests whether the given state tuple can be a final state. A state
  // is final iff there is no observed input in the buffer.
  bool CanBeFinal(const vector<Label> &state) {
    return IsEmptyBuffer(BufferBegin(state), BufferEnd(state));
  }

  // Finds state corresponding to an n-gram. Creates new state if n-gram not
  // found.
  StateId FindState(const vector<Label> &ngram) {
    StateId sparse = ngrams_.FindId(ngram, true);
    StateId dense = condensed_.FindId(sparse, true);
    return dense;
  }

  // Appends after `output` the state tuple corresponding to the state id. The
  // state id must exist.
  void FillState(StateId s, vector<Label> *output) {
    s = condensed_.FindEntry(s);
    for (NGramIterator it = ngrams_.FindSet(s); !it.Done(); it.Next()) {
      Label label = it.Element();
      output->push_back(label);
    }
  }

  // Shifts the buffer in `state` by appending `ilabel` and popping
  // the one in the front as the return value. `next_stub_` is a
  // shifted buffer of size `delay_` where the first `delay_ - 1`
  // elements are the last `delay_ - 1` elements in the buffer of
  // `state`. The last (if any) element in `next_stub_` will be
  // `ilabel` after the call returns.
  Label ShiftBuffer(const vector<Label> &state, Label ilabel,
                    vector<Label> *next_stub_);

  // Builds an arc from state tuple `state` consuming `ilabel` and
  // `olabel`. `next_stub_` is the buffer filled in `ShiftBuffer`.
  Arc MakeArc(const vector<Label> &state, Label ilabel, Label olabel,
              vector<Label> *next_stub_);

  // Expands arcs from state `s`, equivalent to state tuple `state`,
  // with input `ilabel`. `next_stub_` is the buffer filled in
  // `ShiftBuffer`.
  void ExpandArcs(StateId s, const vector<Label> &state, Label ilabel,
                  vector<Label> *next_stub_);

  // Appends arcs from state `s`, equivalent to state tuple `state`,
  // with input `ilabel` to `arcs`. `next_stub_` is the buffer filled
  // in `ShiftBuffer`.
  void AppendArcs(StateId s, const vector<Label> &state, Label ilabel,
                  vector<Label> *next_stub_, vector<Arc> *arcs);

  const LinearFstData<A> *data_;
  size_t delay_;
  // Mapping from internal state tuple to *non-consecutive* ids
  Collection<StateId, Label> ngrams_;
  // Mapping from non-consecutive id to actual state id
  CompactHashBiTable<StateId, StateId, std::hash<StateId> > condensed_;
  // Two frequently used vectors, reuse to avoid repeated heap
  // allocation
  vector<Label> state_stub_, next_stub_;

  void operator=(const LinearTaggerFstImpl<A> &);  // Disallow assignment
};

template <class A>
const int LinearTaggerFstImpl<A>::kMinFileVersion = 1;

template <class A>
const int LinearTaggerFstImpl<A>::kFileVersion = 1;

template <class A>
inline typename A::Label LinearTaggerFstImpl<A>::ShiftBuffer(
    const vector<Label> &state, Label ilabel, vector<Label> *next_stub_) {
  DCHECK(ilabel > 0 || ilabel == LinearFstData<A>::kEndOfSentence);
  if (delay_ == 0) {
    DCHECK_GT(ilabel, 0);
    return ilabel;
  } else {
    (*next_stub_)[BufferEnd(*next_stub_) - next_stub_->begin() - 1] = ilabel;
    return *BufferBegin(state);
  }
}

template <class A>
inline A LinearTaggerFstImpl<A>::MakeArc(const vector<Label> &state,
                                         Label ilabel, Label olabel,
                                         vector<Label> *next_stub_) {
  DCHECK(ilabel > 0 || ilabel == LinearFstData<A>::kEndOfSentence);
  DCHECK(olabel > 0 || olabel == LinearFstData<A>::kStartOfSentence);
  Weight weight(Weight::One());
  data_->TakeTransition(BufferEnd(state), InternalBegin(state),
                        InternalEnd(state), ilabel, olabel, next_stub_,
                        &weight);
  StateId nextstate = FindState(*next_stub_);
  // Restore `next_stub_` to its size before the call
  next_stub_->resize(delay_);
  // In the actual arc, we use epsilons instead of boundaries.
  return A(ilabel == LinearFstData<A>::kEndOfSentence ? 0 : ilabel,
           olabel == LinearFstData<A>::kStartOfSentence ? 0 : olabel, weight,
           nextstate);
}

template <class A>
inline void LinearTaggerFstImpl<A>::ExpandArcs(StateId s,
                                               const vector<Label> &state,
                                               Label ilabel,
                                               vector<Label> *next_stub_) {
  // Input label to constrain the output with, observed `delay_` steps
  // back. `ilabel` is the input label to be put on the arc, which
  // fires features.
  Label obs_ilabel = ShiftBuffer(state, ilabel, next_stub_);
  if (obs_ilabel == LinearFstData<A>::kStartOfSentence) {
    // This happens when input is shorter than `delay_`.
    PushArc(s, MakeArc(state, ilabel, LinearFstData<A>::kStartOfSentence,
                       next_stub_));
  } else {
    std::pair<typename vector<typename A::Label>::const_iterator,
              typename vector<typename A::Label>::const_iterator> range =
        data_->PossibleOutputLabels(obs_ilabel);
    for (typename vector<typename A::Label>::const_iterator it = range.first;
         it != range.second; ++it)
      PushArc(s, MakeArc(state, ilabel, *it, next_stub_));
  }
}

// TODO(wuke): this has much in duplicate with `ExpandArcs()`
template <class A>
inline void LinearTaggerFstImpl<A>::AppendArcs(StateId /*s*/,
                                               const vector<Label> &state,
                                               Label ilabel,
                                               vector<Label> *next_stub_,
                                               vector<Arc> *arcs) {
  // Input label to constrain the output with, observed `delay_` steps
  // back. `ilabel` is the input label to be put on the arc, which
  // fires features.
  Label obs_ilabel = ShiftBuffer(state, ilabel, next_stub_);
  if (obs_ilabel == LinearFstData<A>::kStartOfSentence) {
    // This happens when input is shorter than `delay_`.
    arcs->push_back(
        MakeArc(state, ilabel, LinearFstData<A>::kStartOfSentence, next_stub_));
  } else {
    std::pair<typename vector<typename A::Label>::const_iterator,
              typename vector<typename A::Label>::const_iterator> range =
        data_->PossibleOutputLabels(obs_ilabel);
    for (typename vector<typename A::Label>::const_iterator it = range.first;
         it != range.second; ++it)
      arcs->push_back(MakeArc(state, ilabel, *it, next_stub_));
  }
}

template <class A>
void LinearTaggerFstImpl<A>::Expand(StateId s) {
  VLOG(3) << "Expand " << s;
  state_stub_.clear();
  FillState(s, &state_stub_);

  // Precompute the first `delay_ - 1` elements in the buffer of
  // next states, which are identical for different input/output.
  next_stub_.clear();
  next_stub_.resize(delay_);
  if (delay_ > 0)
    std::copy(BufferBegin(state_stub_) + 1, BufferEnd(state_stub_),
              next_stub_.begin());

  // Epsilon transition for flushing out the next observed input
  if (!IsEmptyBuffer(BufferBegin(state_stub_), BufferEnd(state_stub_)))
    ExpandArcs(s, state_stub_, LinearFstData<A>::kEndOfSentence, &next_stub_);

  // Non-epsilon input when we haven't flushed
  if (delay_ == 0 ||
      *(BufferEnd(state_stub_) - 1) != LinearFstData<A>::kEndOfSentence)
    for (Label ilabel = data_->MinInputLabel();
         ilabel <= data_->MaxInputLabel(); ++ilabel)
      ExpandArcs(s, state_stub_, ilabel, &next_stub_);

  SetArcs(s);
}

template <class A>
void LinearTaggerFstImpl<A>::MatchInput(StateId s, Label ilabel,
                                        vector<Arc> *arcs) {
  state_stub_.clear();
  FillState(s, &state_stub_);

  // Precompute the first `delay_ - 1` elements in the buffer of
  // next states, which are identical for different input/output.
  next_stub_.clear();
  next_stub_.resize(delay_);
  if (delay_ > 0)
    std::copy(BufferBegin(state_stub_) + 1, BufferEnd(state_stub_),
              next_stub_.begin());

  if (ilabel == 0) {
    // Epsilon transition for flushing out the next observed input
    if (!IsEmptyBuffer(BufferBegin(state_stub_), BufferEnd(state_stub_)))
      AppendArcs(s, state_stub_, LinearFstData<A>::kEndOfSentence, &next_stub_,
                 arcs);
  } else {
    // Non-epsilon input when we haven't flushed
    if (delay_ == 0 ||
        *(BufferEnd(state_stub_) - 1) != LinearFstData<A>::kEndOfSentence)
      AppendArcs(s, state_stub_, ilabel, &next_stub_, arcs);
  }
}

template <class A>
inline LinearTaggerFstImpl<A> *LinearTaggerFstImpl<A>::Read(
    istream &strm, const FstReadOptions &opts) {  // NOLINT
  LinearTaggerFstImpl<A> *impl = new LinearTaggerFstImpl<A>;
  FstHeader header;
  if (!impl->ReadHeader(strm, opts, kMinFileVersion, &header)) {
    delete impl;
    return NULL;
  }
  delete impl->data_;
  impl->data_ = LinearFstData<A>::Read(strm);
  if (!impl->data_) {
    delete impl;
    return NULL;
  }
  impl->delay_ = impl->data_->MaxFutureSize();
  impl->ReserveStubSpace();
  return impl;
}

// This class attaches interface to implementation and handles
// reference counting, delegating most methods to ImplToFst.
template <class A>
class LinearTaggerFst : public ImplToFst<LinearTaggerFstImpl<A> > {
 public:
  friend class ArcIterator<LinearTaggerFst<A> >;
  friend class StateIterator<LinearTaggerFst<A> >;
  friend class LinearFstMatcherTpl<LinearTaggerFst<A> >;

  typedef A Arc;
  typedef typename A::Label Label;
  typedef typename A::Weight Weight;
  typedef typename A::StateId StateId;
  typedef DefaultCacheStore<A> Store;
  typedef typename Store::State State;
  typedef LinearTaggerFstImpl<A> Impl;

  LinearTaggerFst() : ImplToFst<Impl>(new Impl) {}

  explicit LinearTaggerFst(LinearFstData<A> *data, SymbolTable *isyms = NULL,
                           SymbolTable *osyms = NULL, bool owner = true,
                           CacheOptions opts = CacheOptions())
      : ImplToFst<Impl>(new Impl(data, isyms, osyms, owner, opts)) {}

  explicit LinearTaggerFst(LinearTaggerFstImpl<A> *impl)
      : ImplToFst<Impl>(impl) {}

  explicit LinearTaggerFst(const Fst<A> &fst) {
    LOG(FATAL) << "LinearTaggerFst: no constructor from arbitrary FST.";
  }

  // See Fst<>::Copy() for doc.
  LinearTaggerFst(const LinearTaggerFst<A> &fst, bool safe = false)
      : ImplToFst<Impl>(fst, safe) {}

  // Get a copy of this LinearTaggerFst. See Fst<>::Copy() for further doc.
  virtual LinearTaggerFst<A> *Copy(bool safe = false) const {
    return new LinearTaggerFst<A>(*this, safe);
  }

  virtual inline void InitStateIterator(StateIteratorData<A> *data) const;

  virtual void InitArcIterator(StateId s, ArcIteratorData<A> *data) const {
    GetImpl()->InitArcIterator(s, data);
  }

  virtual MatcherBase<A> *InitMatcher(MatchType match_type) const {
    return new LinearFstMatcherTpl<LinearTaggerFst<A> >(*this, match_type);
  }

  static LinearTaggerFst<A> *Read(const string &filename) {
    if (!filename.empty()) {
      ifstream strm(filename.c_str(), ifstream::in | ifstream::binary);
      if (!strm) {
        LOG(ERROR) << "LinearTaggerFst::Read: Can't open file: " << filename;
        return 0;
      }
      return Read(strm, FstReadOptions(filename));
    } else {
      return Read(cin, FstReadOptions("standard input"));
    }
  }

  static LinearTaggerFst<A> *Read(istream &in,  // NOLINT
                                  const FstReadOptions &opts) {
    LinearTaggerFstImpl<A> *impl = LinearTaggerFstImpl<A>::Read(in, opts);
    return impl ? new LinearTaggerFst<A>(impl) : NULL;
  }

  virtual bool Write(const string &filename) const {
    if (!filename.empty()) {
      ofstream strm(filename.c_str(), ofstream::out | ofstream::binary);
      if (!strm) {
        LOG(ERROR) << "LinearTaggerFst::Write: Can't open file: " << filename;
        return false;
      }
      return Write(strm, FstWriteOptions(filename));
    } else {
      return Write(cout, FstWriteOptions("standard output"));
    }
  }

  virtual bool Write(ostream &strm,  // NOLINT
                     const FstWriteOptions &opts) const {
    return GetImpl()->Write(strm, opts);
  }

 private:
  // Makes visible to friends.
  Impl *GetImpl() const { return ImplToFst<Impl>::GetImpl(); }

  void operator=(const LinearTaggerFst<A> &fst);  // Disallow assignment
};

// Specialization for LinearTaggerFst.
template <class A>
class StateIterator<LinearTaggerFst<A> > : public CacheStateIterator<
    LinearTaggerFst<A> > {
 public:
  explicit StateIterator(const LinearTaggerFst<A> &fst)
      : CacheStateIterator<LinearTaggerFst<A> >(fst, fst.GetImpl()) {}
};

// Specialization for LinearTaggerFst.
template <class A>
class ArcIterator<LinearTaggerFst<A> > : public CacheArcIterator<
    LinearTaggerFst<A> > {
 public:
  typedef typename A::StateId StateId;

  ArcIterator(const LinearTaggerFst<A> &fst, StateId s)
      : CacheArcIterator<LinearTaggerFst<A> >(fst.GetImpl(), s) {
    if (!fst.GetImpl()->HasArcs(s)) fst.GetImpl()->Expand(s);
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(ArcIterator);
};

template <class A>
inline void LinearTaggerFst<A>::InitStateIterator(
    StateIteratorData<A> *data) const {
  data->base = new StateIterator<LinearTaggerFst<A> >(*this);
}

// Implementation class for on-the-fly generated LinearClassifierFst with
// special optimization in matching.
template <class A>
class LinearClassifierFstImpl : public CacheImpl<A> {
 public:
  using FstImpl<A>::SetType;
  using FstImpl<A>::SetProperties;
  using FstImpl<A>::SetInputSymbols;
  using FstImpl<A>::SetOutputSymbols;
  using FstImpl<A>::WriteHeader;

  using CacheBaseImpl<CacheState<A> >::PushArc;
  using CacheBaseImpl<CacheState<A> >::HasArcs;
  using CacheBaseImpl<CacheState<A> >::HasFinal;
  using CacheBaseImpl<CacheState<A> >::HasStart;
  using CacheBaseImpl<CacheState<A> >::SetArcs;
  using CacheBaseImpl<CacheState<A> >::SetFinal;
  using CacheBaseImpl<CacheState<A> >::SetStart;

  typedef A Arc;
  typedef typename A::Label Label;
  typedef typename A::Weight Weight;
  typedef typename A::StateId StateId;
  typedef typename Collection<StateId, Label>::SetIterator NGramIterator;

  // Constructs an empty FST by default.
  LinearClassifierFstImpl() : CacheImpl<A>(CacheOptions()) {
    SetType("linear-classifier");
    num_classes_ = 0;
    num_groups_ = 0;
    data_ = new LinearFstData<A>;
  }

  // Constructs the FST with given data storage, number of classes and
  // symbol tables. When `owner` is true, takes over the ownership of
  // `data`.
  LinearClassifierFstImpl(const LinearFstData<Arc> *data, size_t num_classes,
                          SymbolTable *isyms, SymbolTable *osyms, bool owner,
                          CacheOptions opts)
      : CacheImpl<A>(opts),
        data_(data),
        num_classes_(num_classes),
        num_groups_(data_->NumGroups() / num_classes_) {
    SetType("linear-classifier");
    SetProperties(kILabelSorted, kFstProperties);
    if (!owner) data_->IncrRefCount();
    SetInputSymbols(isyms);
    SetOutputSymbols(osyms);
    ReserveStubSpace();
  }

  // Copy by sharing the underlying data storage.
  LinearClassifierFstImpl(const LinearClassifierFstImpl &impl)
      : CacheImpl<A>(impl),
        data_(impl.data_),
        num_classes_(impl.num_classes_),
        num_groups_(impl.num_groups_) {
    SetType("linear-classifier");
    SetProperties(impl.Properties(), kCopyProperties);
    SetInputSymbols(impl.InputSymbols());
    SetOutputSymbols(impl.OutputSymbols());
    data_->IncrRefCount();
    ReserveStubSpace();
  }

  ~LinearClassifierFstImpl() {
    if (data_->DecrRefCount() == 0) delete data_;
  }

  StateId Start() {
    if (!HasStart()) {
      StateId start = FindStartState();
      SetStart(start);
    }
    return CacheImpl<A>::Start();
  }

  Weight Final(StateId s) {
    if (!HasFinal(s)) {
      state_stub_.clear();
      FillState(s, &state_stub_);
      SetFinal(s, FinalWeight(state_stub_));
    }
    return CacheImpl<A>::Final(s);
  }

  size_t NumArcs(StateId s) {
    if (!HasArcs(s)) Expand(s);
    return CacheImpl<A>::NumArcs(s);
  }

  size_t NumInputEpsilons(StateId s) {
    if (!HasArcs(s)) Expand(s);
    return CacheImpl<A>::NumInputEpsilons(s);
  }

  size_t NumOutputEpsilons(StateId s) {
    if (!HasArcs(s)) Expand(s);
    return CacheImpl<A>::NumOutputEpsilons(s);
  }

  void InitArcIterator(StateId s, ArcIteratorData<A> *data) {
    if (!HasArcs(s)) Expand(s);
    CacheImpl<A>::InitArcIterator(s, data);
  }

  // Computes the outgoing transitions from a state, creating new
  // destination states as needed.
  void Expand(StateId s);

  // Appends to `arcs` all out-going arcs from state `s` that matches
  // `label` as the input label.
  void MatchInput(StateId s, Label ilabel, vector<Arc> *arcs);

  static LinearClassifierFstImpl<A> *Read(istream &strm,  // NOLINT
                                          const FstReadOptions &opts);

  bool Write(ostream &strm,  // NOLINT
             const FstWriteOptions &opts) const {
    FstHeader header;
    header.SetStart(kNoStateId);
    WriteHeader(strm, opts, kFileVersion, &header);
    data_->Write(strm);
    WriteType(strm, num_classes_);
    if (!strm) {
      LOG(ERROR) << "LinearClassifierFst::Write: write failed: " << opts.source;
      return false;
    }
    return true;
  }

 private:
  static const int kMinFileVersion;
  static const int kFileVersion;

  // A collection of functions to access parts of the state tuple. A
  // state tuple is a vector of `Label`s with two parts:
  //   [prediction] [internal].
  //
  // - [prediction] is a single label of the predicted class. A state
  //   must have a positive class label, unless it is the start state.
  //
  // - [internal] is the internal state tuple for `LinearFstData` of
  //   the given class; or kNoTrieNodeId's if in start state.
  Label &Prediction(vector<Label> &state) { return state[0]; }  // NOLINT
  Label Prediction(const vector<Label> &state) const { return state[0]; }

  Label &InternalAt(vector<Label> &state, int index) {  // NOLINT
    return state[index + 1];
  }
  Label InternalAt(const vector<Label> &state, int index) const {
    return state[index + 1];
  }

  // The size of state tuples are fixed, reserve them in stubs
  void ReserveStubSpace() {
    size_t size = 1 + num_groups_;
    state_stub_.reserve(size);
    next_stub_.reserve(size);
  }

  // Computes the start state tuple and maps it to the start state id.
  StateId FindStartState() {
    // A start state tuple has no prediction
    state_stub_.clear();
    state_stub_.push_back(kNoLabel);
    // For a start state, we don't yet know where we are in the tries.
    for (size_t i = 0; i < num_groups_; ++i)
      state_stub_.push_back(kNoTrieNodeId);
    return FindState(state_stub_);
  }

  // Tests if the state tuple represents the start state.
  bool IsStartState(const vector<Label> &state) const {
    return state[0] == kNoLabel;
  }

  // Computes the actual group id in the data storage.
  int GroupId(Label pred, int group) const {
    return group * num_classes_ + pred - 1;
  }

  // Finds out the final weight of the given state. A state is final
  // iff it is not the start.
  Weight FinalWeight(const vector<Label> &state) const {
    if (IsStartState(state)) {
      return Weight::Zero();
    }
    Label pred = Prediction(state);
    DCHECK_GT(pred, 0);
    DCHECK_LE(pred, num_classes_);
    Weight final = Weight::One();
    for (size_t group = 0; group < num_groups_; ++group) {
      int group_id = GroupId(pred, group);
      int trie_state = InternalAt(state, group);
      final = Times(final, data_->GroupFinalWeight(group_id, trie_state));
    }
    return final;
  }

  // Finds state corresponding to an n-gram. Creates new state if n-gram not
  // found.
  StateId FindState(const vector<Label> &ngram) {
    StateId sparse = ngrams_.FindId(ngram, true);
    StateId dense = condensed_.FindId(sparse, true);
    return dense;
  }

  // Appends after `output` the state tuple corresponding to the state id. The
  // state id must exist.
  void FillState(StateId s, vector<Label> *output) {
    s = condensed_.FindEntry(s);
    for (NGramIterator it = ngrams_.FindSet(s); !it.Done(); it.Next()) {
      Label label = it.Element();
      output->push_back(label);
    }
  }

  const LinearFstData<A> *data_;
  // Division of groups in `data_`; num_classes_ * num_groups_ ==
  // data_->NumGroups().
  size_t num_classes_, num_groups_;
  // Mapping from internal state tuple to *non-consecutive* ids
  Collection<StateId, Label> ngrams_;
  // Mapping from non-consecutive id to actual state id
  CompactHashBiTable<StateId, StateId, std::hash<StateId> > condensed_;
  // Two frequently used vectors, reuse to avoid repeated heap
  // allocation
  vector<Label> state_stub_, next_stub_;

  void operator=(const LinearClassifierFstImpl<A> &);  // Disallow assignment
};

template <class A>
const int LinearClassifierFstImpl<A>::kMinFileVersion = 0;

template <class A>
const int LinearClassifierFstImpl<A>::kFileVersion = 0;

template <class A>
void LinearClassifierFstImpl<A>::Expand(StateId s) {
  VLOG(3) << "Expand " << s;
  state_stub_.clear();
  FillState(s, &state_stub_);
  next_stub_.clear();
  next_stub_.resize(1 + num_groups_);

  if (IsStartState(state_stub_)) {
    // Make prediction
    for (Label pred = 1; pred <= num_classes_; ++pred) {
      Prediction(next_stub_) = pred;
      for (int i = 0; i < num_groups_; ++i)
        InternalAt(next_stub_, i) = data_->GroupStartState(GroupId(pred, i));
      PushArc(s, A(0, pred, Weight::One(), FindState(next_stub_)));
    }
  } else {
    Label pred = Prediction(state_stub_);
    DCHECK_GT(pred, 0);
    DCHECK_LE(pred, num_classes_);
    for (Label ilabel = data_->MinInputLabel();
         ilabel <= data_->MaxInputLabel(); ++ilabel) {
      Prediction(next_stub_) = pred;
      Weight weight = Weight::One();
      for (int i = 0; i < num_groups_; ++i)
        InternalAt(next_stub_, i) =
            data_->GroupTransition(GroupId(pred, i), InternalAt(state_stub_, i),
                                   ilabel, pred, &weight);
      PushArc(s, A(ilabel, 0, weight, FindState(next_stub_)));
    }
  }

  SetArcs(s);
}

template <class A>
void LinearClassifierFstImpl<A>::MatchInput(StateId s, Label ilabel,
                                            vector<Arc> *arcs) {
  state_stub_.clear();
  FillState(s, &state_stub_);
  next_stub_.clear();
  next_stub_.resize(1 + num_groups_);

  if (IsStartState(state_stub_)) {
    // Make prediction if `ilabel` is epsilon.
    if (ilabel == 0) {
      for (Label pred = 1; pred <= num_classes_; ++pred) {
        Prediction(next_stub_) = pred;
        for (int i = 0; i < num_groups_; ++i)
          InternalAt(next_stub_, i) = data_->GroupStartState(GroupId(pred, i));
        arcs->push_back(A(0, pred, Weight::One(), FindState(next_stub_)));
      }
    }
  } else if (ilabel != 0) {
    Label pred = Prediction(state_stub_);
    Weight weight = Weight::One();
    Prediction(next_stub_) = pred;
    for (int i = 0; i < num_groups_; ++i)
      InternalAt(next_stub_, i) = data_->GroupTransition(
          GroupId(pred, i), InternalAt(state_stub_, i), ilabel, pred, &weight);
    arcs->push_back(A(ilabel, 0, weight, FindState(next_stub_)));
  }
}

template <class A>
inline LinearClassifierFstImpl<A> *LinearClassifierFstImpl<A>::Read(
    istream &strm, const FstReadOptions &opts) {  // NOLINT
  LinearClassifierFstImpl<A> *impl = new LinearClassifierFstImpl<A>;
  FstHeader header;
  if (!impl->ReadHeader(strm, opts, kMinFileVersion, &header)) {
    delete impl;
    return NULL;
  }
  delete impl->data_;
  impl->data_ = LinearFstData<A>::Read(strm);
  if (!impl->data_) {
    delete impl;
    return NULL;
  }
  ReadType(strm, &impl->num_classes_);
  if (!strm) {
    delete impl;
    return NULL;
  }
  impl->num_groups_ = impl->data_->NumGroups() / impl->num_classes_;
  if (impl->num_groups_ * impl->num_classes_ != impl->data_->NumGroups()) {
    FSTERROR() << "total number of feature groups is not a multiple of the "
                  "number of classes: num groups = " << impl->data_->NumGroups()
               << ", num classes = " << impl->num_classes_;
    delete impl;
    return NULL;
  }
  impl->ReserveStubSpace();
  return impl;
}

// This class attaches interface to implementation and handles
// reference counting, delegating most methods to ImplToFst.
template <class A>
class LinearClassifierFst : public ImplToFst<LinearClassifierFstImpl<A> > {
 public:
  friend class ArcIterator<LinearClassifierFst<A> >;
  friend class StateIterator<LinearClassifierFst<A> >;
  friend class LinearFstMatcherTpl<LinearClassifierFst<A> >;

  typedef A Arc;
  typedef typename A::Label Label;
  typedef typename A::Weight Weight;
  typedef typename A::StateId StateId;
  typedef DefaultCacheStore<A> Store;
  typedef typename Store::State State;
  typedef LinearClassifierFstImpl<A> Impl;

  LinearClassifierFst() : ImplToFst<Impl>(new Impl) {}

  explicit LinearClassifierFst(LinearFstData<A> *data, size_t num_classes,
                               SymbolTable *isyms = NULL,
                               SymbolTable *osyms = NULL, bool owner = true,
                               CacheOptions opts = CacheOptions())
      : ImplToFst<Impl>(new Impl(data, num_classes, isyms, osyms, owner,
                                 opts)) {}

  explicit LinearClassifierFst(LinearClassifierFstImpl<A> *impl)
      : ImplToFst<Impl>(impl) {}

  explicit LinearClassifierFst(const Fst<A> &fst) {
    LOG(FATAL) << "LinearClassifierFst: no constructor from arbitrary FST.";
  }

  // See Fst<>::Copy() for doc.
  LinearClassifierFst(const LinearClassifierFst<A> &fst, bool safe = false)
      : ImplToFst<Impl>(fst, safe) {}

  // Get a copy of this LinearClassifierFst. See Fst<>::Copy() for further doc.
  virtual LinearClassifierFst<A> *Copy(bool safe = false) const {
    return new LinearClassifierFst<A>(*this, safe);
  }

  virtual inline void InitStateIterator(StateIteratorData<A> *data) const;

  virtual void InitArcIterator(StateId s, ArcIteratorData<A> *data) const {
    GetImpl()->InitArcIterator(s, data);
  }

  virtual MatcherBase<A> *InitMatcher(MatchType match_type) const {
    return new LinearFstMatcherTpl<LinearClassifierFst<A> >(*this, match_type);
  }

  static LinearClassifierFst<A> *Read(const string &filename) {
    if (!filename.empty()) {
      ifstream strm(filename.c_str(), ifstream::in | ifstream::binary);
      if (!strm) {
        LOG(ERROR) << "LinearClassifierFst::Read: Can't open file: "
                   << filename;
        return 0;
      }
      return Read(strm, FstReadOptions(filename));
    } else {
      return Read(cin, FstReadOptions("standard input"));
    }
  }

  static LinearClassifierFst<A> *Read(istream &in,  // NOLINT
                                      const FstReadOptions &opts) {
    LinearClassifierFstImpl<A> *impl =
        LinearClassifierFstImpl<A>::Read(in, opts);
    return impl ? new LinearClassifierFst<A>(impl) : NULL;
  }

  virtual bool Write(const string &filename) const {
    if (!filename.empty()) {
      ofstream strm(filename.c_str(), ofstream::out | ofstream::binary);
      if (!strm) {
        LOG(ERROR) << "ProdLmFst::Write: Can't open file: " << filename;
        return false;
      }
      return Write(strm, FstWriteOptions(filename));
    } else {
      return Write(cout, FstWriteOptions("standard output"));
    }
  }

  virtual bool Write(ostream &strm,  // NOLINT
                     const FstWriteOptions &opts) const {
    return GetImpl()->Write(strm, opts);
  }

 private:
  // Makes visible to friends.
  Impl *GetImpl() const { return ImplToFst<Impl>::GetImpl(); }

  void operator=(const LinearClassifierFst<A> &fst);  // Disallow assignment
};

// Specialization for LinearClassifierFst.
template <class A>
class StateIterator<LinearClassifierFst<A> > : public CacheStateIterator<
    LinearClassifierFst<A> > {
 public:
  explicit StateIterator(const LinearClassifierFst<A> &fst)
      : CacheStateIterator<LinearClassifierFst<A> >(fst, fst.GetImpl()) {}
};

// Specialization for LinearClassifierFst.
template <class A>
class ArcIterator<LinearClassifierFst<A> > : public CacheArcIterator<
    LinearClassifierFst<A> > {
 public:
  typedef typename A::StateId StateId;

  ArcIterator(const LinearClassifierFst<A> &fst, StateId s)
      : CacheArcIterator<LinearClassifierFst<A> >(fst.GetImpl(), s) {
    if (!fst.GetImpl()->HasArcs(s)) fst.GetImpl()->Expand(s);
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(ArcIterator);
};

template <class A>
inline void LinearClassifierFst<A>::InitStateIterator(
    StateIteratorData<A> *data) const {
  data->base = new StateIterator<LinearClassifierFst<A> >(*this);
}

// Specialized Matcher for LinearFsts. This matcher only supports
// matching from the input side. This is intentional because comparing
// the scores of different input sequences with the same output
// sequence is meaningless in a discriminative model.
template <class F>
class LinearFstMatcherTpl : public MatcherBase<typename F::Arc> {
 public:
  typedef typename F::Arc Arc;
  typedef typename Arc::Label Label;
  typedef typename Arc::Weight Weight;
  typedef typename Arc::StateId StateId;
  typedef F FST;

  LinearFstMatcherTpl(const FST &fst, MatchType match_type)
      : fst_(fst.Copy()),
        match_type_(match_type),
        s_(kNoStateId),
        current_loop_(false),
        loop_(kNoLabel, 0, Weight::One(), kNoStateId),
        cur_arc_(0),
        error_(false) {
    switch (match_type_) {
      case MATCH_INPUT:
      case MATCH_OUTPUT:
      case MATCH_NONE:
        break;
      default:
        FSTERROR() << "LinearFstMatcherTpl: bad match type";
        match_type_ = MATCH_NONE;
        error_ = true;
    }
  }

  LinearFstMatcherTpl(const LinearFstMatcherTpl<F> &matcher, bool safe = false)
      : fst_(matcher.fst_->Copy(safe)),
        match_type_(matcher.match_type_),
        s_(kNoStateId),
        current_loop_(false),
        loop_(matcher.loop_),
        cur_arc_(0),
        error_(matcher.error_) {}

  virtual ~LinearFstMatcherTpl() { delete fst_; }

  virtual LinearFstMatcherTpl<F> *Copy(bool safe = false) const {
    return new LinearFstMatcherTpl<F>(*this, safe);
  }

  virtual MatchType Type(bool /*test*/) const {
    // `MATCH_INPUT` is the only valid type
    return match_type_ == MATCH_INPUT ? match_type_ : MATCH_NONE;
  }

  void SetState(StateId s) {
    if (s_ == s) return;
    s_ = s;
    // `MATCH_INPUT` is the only valid type
    if (match_type_ != MATCH_INPUT) {
      FSTERROR() << "LinearFstMatcherTpl: bad match type";
      error_ = true;
    }
    loop_.nextstate = s;
  }

  bool Find(Label label) {
    if (error_) {
      current_loop_ = false;
      return false;
    }
    current_loop_ = label == 0;
    if (label == kNoLabel) label = 0;
    arcs_.clear();
    cur_arc_ = 0;
    fst_->GetImpl()->MatchInput(s_, label, &arcs_);
    return current_loop_ || !arcs_.empty();
  }

  bool Done() const { return !(current_loop_ || cur_arc_ < arcs_.size()); }

  const Arc &Value() const { return current_loop_ ? loop_ : arcs_[cur_arc_]; }

  void Next() {
    if (current_loop_)
      current_loop_ = false;
    else
      ++cur_arc_;
  }

  ssize_t Priority_(StateId s) { return kRequirePriority; }

  virtual const FST &GetFst() const { return *fst_; }

  virtual uint64 Properties(uint64 props) const {
    if (error_) props |= kError;
    return props;
  }

  virtual uint32 Flags() const { return kRequireMatch; }

 private:
  virtual void SetState_(StateId s) { SetState(s); }
  virtual bool Find_(Label label) { return Find(label); }
  virtual bool Done_() const { return Done(); }
  virtual const Arc &Value_() const { return Value(); }
  virtual void Next_() { Next(); }

  const FST *fst_;
  MatchType match_type_;  // Type of match to perform
  StateId s_;             // Current state
  bool current_loop_;     // Current arc is the implicit loop
  Arc loop_;              // For non-consuming symbols
  vector<Arc> arcs_;  // All out-going arcs matching the label in last `Find()`
                      // call
  size_t cur_arc_;    // Index to the arc that `Value()` should return
  bool error_;        // Error encountered

  void operator=(const LinearFstMatcherTpl<F> &);  // Disallow assignment
};
}  // namespace fst

#endif  // FST_EXTENSIONS_LINEAR_LINEAR_FST_H_
