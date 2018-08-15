// sparse-tuple-weight.h

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
// Author: krr@google.com (Kasturi Rangan Raghavan)
// Inspiration: allauzen@google.com (Cyril Allauzen)
// \file
// Sparse version of tuple-weight, based on tuple-weight.h
//   Internally stores sparse key, value pairs in linked list
//   Default value elemnt is the assumed value of unset keys
//   Internal singleton implementation that stores first key,
//   value pair as a initialized member variable to avoide
//   unnecessary allocation on heap.
// Use SparseTupleWeightIterator to iterate through the key,value pairs
// Note: this does NOT iterate through the default value.
//
// Sparse tuple weight set operation definitions.

#ifndef FST_LIB_SPARSE_TUPLE_WEIGHT_H__
#define FST_LIB_SPARSE_TUPLE_WEIGHT_H__

#include<string>
#include<list>
#include<stack>
#include<unordered_map>
using std::unordered_map;
using std::unordered_multimap;

#include <fst/weight.h>


DECLARE_string(fst_weight_parentheses);
DECLARE_string(fst_weight_separator);

namespace fst {

template <class W, class K> class SparseTupleWeight;

template<class W, class K>
class SparseTupleWeightIterator;

template <class W, class K>
istream &operator>>(istream &strm, SparseTupleWeight<W, K> &w);

// Arbitrary dimension tuple weight, stored as a sorted linked-list
// W is any weight class,
// K is the key value type. kNoKey(-1) is reserved for internal use
template <class W, class K = int>
class SparseTupleWeight {
 public:
  typedef pair<K, W> Pair;
  typedef SparseTupleWeight<typename W::ReverseWeight, K> ReverseWeight;

  const static K kNoKey = -1;
  SparseTupleWeight() {
    Init();
  }

  template <class Iterator>
  SparseTupleWeight(Iterator begin, Iterator end) {
    Init();
    // Assumes input iterator is sorted
    for (Iterator it = begin; it != end; ++it)
      Push(*it);
  }


  SparseTupleWeight(const K& key, const W &w) {
    Init();
    Push(key, w);
  }

  SparseTupleWeight(const W &w) {
    Init(w);
  }

  SparseTupleWeight(const SparseTupleWeight<W, K> &w) {
    Init(w.DefaultValue());
    SetDefaultValue(w.DefaultValue());
    for (SparseTupleWeightIterator<W, K> it(w); !it.Done(); it.Next()) {
      Push(it.Value());
    }
  }

  static const SparseTupleWeight<W, K> &Zero() {
    static SparseTupleWeight<W, K> zero;
    return zero;
  }

  static const SparseTupleWeight<W, K> &One() {
    static SparseTupleWeight<W, K> one(W::One());
    return one;
  }

  static const SparseTupleWeight<W, K> &NoWeight() {
    static SparseTupleWeight<W, K> no_weight(W::NoWeight());
    return no_weight;
  }

  istream &Read(istream &strm) {
    ReadType(strm, &default_);
    ReadType(strm, &first_);
    return ReadType(strm, &rest_);
  }

  ostream &Write(ostream &strm) const {
    WriteType(strm, default_);
    WriteType(strm, first_);
    return WriteType(strm, rest_);
  }

  SparseTupleWeight<W, K> &operator=(const SparseTupleWeight<W, K> &w) {
    if (this == &w) return *this; // check for w = w
    Init(w.DefaultValue());
    for (SparseTupleWeightIterator<W, K> it(w); !it.Done(); it.Next()) {
      Push(it.Value());
    }
    return *this;
  }

  bool Member() const {
    if (!DefaultValue().Member()) return false;
    for (SparseTupleWeightIterator<W, K> it(*this); !it.Done(); it.Next()) {
      if (!it.Value().second.Member()) return false;
    }
    return true;
  }

  // Assumes H() function exists for the hash of the key value
  size_t Hash() const {
    uint64 h = 0;
    std::hash<K> H;
    for (SparseTupleWeightIterator<W, K> it(*this); !it.Done(); it.Next()) {
      h = 5 * h + H(it.Value().first);
      h = 13 * h + it.Value().second.Hash();
    }
    return size_t(h);
  }

  SparseTupleWeight<W, K> Quantize(float delta = kDelta) const {
    SparseTupleWeight<W, K> w;
    for (SparseTupleWeightIterator<W, K> it(*this); !it.Done(); it.Next()) {
      w.Push(it.Value().first, it.Value().second.Quantize(delta));
    }
    return w;
  }

  ReverseWeight Reverse() const {
    SparseTupleWeight<W, K> w;
    for (SparseTupleWeightIterator<W, K> it(*this); !it.Done(); it.Next()) {
      w.Push(it.Value().first, it.Value().second.Reverse());
    }
    return w;
  }

  // Common initializer among constructors.
  void Init() {
    Init(W::Zero());
  }

  void Init(const W& default_value) {
    first_.first = kNoKey;
    /* initialized to the reserved key value */
    default_ = default_value;
    rest_.clear();
  }

  size_t Size() const {
    if (first_.first == kNoKey)
      return 0;
    else
      return  rest_.size() + 1;
  }

  inline void Push(const K &k, const W &w, bool default_value_check = true) {
    Push(make_pair(k, w), default_value_check);
  }

  inline void Push(const Pair &p, bool default_value_check = true) {
    if (default_value_check && p.second == default_) return;
    if (first_.first == kNoKey) {
      first_ = p;
    } else {
      rest_.push_back(p);
    }
  }

  void SetDefaultValue(const W& val) { default_ = val; }

  const W& DefaultValue() const { return default_; }

 protected:
  static istream& ReadNoParen(
    istream&, SparseTupleWeight<W, K>&, char separator);

  static istream& ReadWithParen(
    istream&, SparseTupleWeight<W, K>&,
    char separator, char open_paren, char close_paren);

 private:
  // Assumed default value of uninitialized keys, by default W::Zero()
  W default_;

  // Key values pairs are first stored in first_, then fill rest_
  // this way we can avoid dynamic allocation in the common case
  // where the weight is a single key,val pair.
  Pair first_;
  list<Pair> rest_;

  friend istream &operator>><W, K>(istream&, SparseTupleWeight<W, K>&);
  friend class SparseTupleWeightIterator<W, K>;
};

template<class W, class K>
class SparseTupleWeightIterator {
 public:
  typedef typename SparseTupleWeight<W, K>::Pair Pair;
  typedef typename list<Pair>::const_iterator const_iterator;
  typedef typename list<Pair>::iterator iterator;

  explicit SparseTupleWeightIterator(const SparseTupleWeight<W, K>& w)
    : first_(w.first_), rest_(w.rest_), init_(true),
      iter_(rest_.begin()) {}

  bool Done() const {
    if (init_)
      return first_.first == SparseTupleWeight<W, K>::kNoKey;
    else
      return iter_ == rest_.end();
  }

  const Pair& Value() const { return init_ ? first_ : *iter_; }

  void Next() {
    if (init_)
      init_ = false;
    else
      ++iter_;
  }

  void Reset() {
    init_ = true;
    iter_ = rest_.begin();
  }

 private:
  const Pair &first_;
  const list<Pair> & rest_;
  bool init_;  // in the initialized state?
  typename list<Pair>::const_iterator iter_;

  DISALLOW_COPY_AND_ASSIGN(SparseTupleWeightIterator);
};

template<class W, class K, class M>
inline void SparseTupleWeightMap(
  SparseTupleWeight<W, K>* ret,
  const SparseTupleWeight<W, K>& w1,
  const SparseTupleWeight<W, K>& w2,
  const M& operator_mapper) {
  SparseTupleWeightIterator<W, K> w1_it(w1);
  SparseTupleWeightIterator<W, K> w2_it(w2);
  const W& v1_def = w1.DefaultValue();
  const W& v2_def = w2.DefaultValue();
  ret->SetDefaultValue(operator_mapper.Map(0, v1_def, v2_def));
  while (!w1_it.Done() || !w2_it.Done()) {
    const K& k1 = (w1_it.Done()) ? w2_it.Value().first : w1_it.Value().first;
    const K& k2 = (w2_it.Done()) ? w1_it.Value().first : w2_it.Value().first;
    const W& v1 = (w1_it.Done()) ? v1_def : w1_it.Value().second;
    const W& v2 = (w2_it.Done()) ? v2_def : w2_it.Value().second;
    if (k1 == k2) {
      ret->Push(k1, operator_mapper.Map(k1, v1, v2));
      if (!w1_it.Done()) w1_it.Next();
      if (!w2_it.Done()) w2_it.Next();
    } else if (k1 < k2) {
      ret->Push(k1, operator_mapper.Map(k1, v1, v2_def));
      w1_it.Next();
    } else {
      ret->Push(k2, operator_mapper.Map(k2, v1_def, v2));
      w2_it.Next();
    }
  }
}

template <class W, class K>
inline bool operator==(const SparseTupleWeight<W, K> &w1,
                       const SparseTupleWeight<W, K> &w2) {
  const W& v1_def = w1.DefaultValue();
  const W& v2_def = w2.DefaultValue();
  if (v1_def != v2_def) return false;

  SparseTupleWeightIterator<W, K> w1_it(w1);
  SparseTupleWeightIterator<W, K> w2_it(w2);
  while (!w1_it.Done() || !w2_it.Done()) {
    const K& k1 = (w1_it.Done()) ? w2_it.Value().first : w1_it.Value().first;
    const K& k2 = (w2_it.Done()) ? w1_it.Value().first : w2_it.Value().first;
    const W& v1 = (w1_it.Done()) ? v1_def : w1_it.Value().second;
    const W& v2 = (w2_it.Done()) ? v2_def : w2_it.Value().second;
    if (k1 == k2) {
      if (v1 != v2) return false;
      if (!w1_it.Done()) w1_it.Next();
      if (!w2_it.Done()) w2_it.Next();
    } else if (k1 < k2) {
      if (v1 != v2_def) return false;
      w1_it.Next();
    } else {
      if (v1_def != v2) return false;
      w2_it.Next();
    }
  }
  return true;
}

template <class W, class K>
inline bool operator!=(const SparseTupleWeight<W, K> &w1,
                       const SparseTupleWeight<W, K> &w2) {
  return !(w1 == w2);
}

template <class W, class K>
inline ostream &operator<<(ostream &strm, const SparseTupleWeight<W, K> &w) {
  if(FLAGS_fst_weight_separator.size() != 1) {
    FSTERROR() << "FLAGS_fst_weight_separator.size() is not equal to 1";
    strm.clear(std::ios::badbit);
    return strm;
  }
  char separator = FLAGS_fst_weight_separator[0];
  bool write_parens = false;
  if (!FLAGS_fst_weight_parentheses.empty()) {
    if (FLAGS_fst_weight_parentheses.size() != 2) {
      FSTERROR() << "FLAGS_fst_weight_parentheses.size() is not equal to 2";
      strm.clear(std::ios::badbit);
      return strm;
    }
    write_parens = true;
  }

  if (write_parens)
    strm << FLAGS_fst_weight_parentheses[0];

  strm << w.DefaultValue();
  strm << separator;

  size_t n = w.Size();
  strm << n;
  strm << separator;

  for (SparseTupleWeightIterator<W, K> it(w); !it.Done(); it.Next()) {
      strm << it.Value().first;
      strm << separator;
      strm << it.Value().second;
      strm << separator;
  }

  if (write_parens)
    strm << FLAGS_fst_weight_parentheses[1];

  return strm;
}

template <class W, class K>
inline istream &operator>>(istream &strm, SparseTupleWeight<W, K> &w) {
  if(FLAGS_fst_weight_separator.size() != 1) {
    FSTERROR() << "FLAGS_fst_weight_separator.size() is not equal to 1";
    strm.clear(std::ios::badbit);
    return strm;
  }
  char separator = FLAGS_fst_weight_separator[0];

  if (!FLAGS_fst_weight_parentheses.empty()) {
    if (FLAGS_fst_weight_parentheses.size() != 2) {
      FSTERROR() << "FLAGS_fst_weight_parentheses.size() is not equal to 2";
      strm.clear(std::ios::badbit);
      return strm;
    }
    return SparseTupleWeight<W, K>::ReadWithParen(
        strm, w, separator, FLAGS_fst_weight_parentheses[0],
        FLAGS_fst_weight_parentheses[1]);
  } else {
    return SparseTupleWeight<W, K>::ReadNoParen(strm, w, separator);
  }
}

// Reads SparseTupleWeight when there are no parentheses around tuple terms
template <class W, class K>
inline istream& SparseTupleWeight<W, K>::ReadNoParen(
    istream &strm,
    SparseTupleWeight<W, K> &w,
    char separator) {
  int c;
  size_t n;

  do {
    c = strm.get();
  } while (isspace(c));


  { // Read default weight
    W default_value;
    string s;
    while (c != separator) {
      if (c == EOF) {
        strm.clear(std::ios::badbit);
        return strm;
      }
      s += c;
      c = strm.get();
    }
    istringstream sstrm(s);
    sstrm >> default_value;
    w.SetDefaultValue(default_value);
  }

  c = strm.get();

  { // Read n
    string s;
    while (c != separator) {
      if (c == EOF) {
        strm.clear(std::ios::badbit);
        return strm;
      }
      s += c;
      c = strm.get();
    }
    istringstream sstrm(s);
    sstrm >> n;
  }

  // Read n elements
  for (size_t i = 0; i < n; ++i) {
    // discard separator
    c = strm.get();
    K p;
    W r;

    { // read key
      string s;
      while (c != separator) {
        if (c == EOF) {
          strm.clear(std::ios::badbit);
          return strm;
        }
        s += c;
        c = strm.get();
      }
      istringstream sstrm(s);
      sstrm >> p;
    }

    c = strm.get();

    { // read weight
      string s;
      while (c != separator) {
        if (c == EOF) {
          strm.clear(std::ios::badbit);
          return strm;
        }
        s += c;
        c = strm.get();
      }
      istringstream sstrm(s);
      sstrm >> r;
    }

    w.Push(p, r);
  }

  c = strm.get();
  if (c != separator) {
    strm.clear(std::ios::badbit);
  }

  return strm;
}

// Reads SparseTupleWeight when there are parentheses around tuple terms
template <class W, class K>
inline istream& SparseTupleWeight<W, K>::ReadWithParen(
    istream &strm,
    SparseTupleWeight<W, K> &w,
    char separator,
    char open_paren,
    char close_paren) {
  int c;
  size_t n;

  do {
    c = strm.get();
  } while (isspace(c));

  if (c != open_paren) {
    FSTERROR() << "is fst_weight_parentheses flag set correcty? ";
    strm.clear(std::ios::badbit);
    return strm;
  }

  c = strm.get();

  { // Read weight
    W default_value;
    stack<int> parens;
    string s;
    while (c != separator || !parens.empty()) {
      if (c == EOF) {
        strm.clear(std::ios::badbit);
        return strm;
      }
      s += c;
      // If parens encountered before separator, they must be matched
      if (c == open_paren) {
        parens.push(1);
      } else if (c == close_paren) {
        // Fail for mismatched parens
        if (parens.empty()) {
          strm.clear(std::ios::failbit);
          return strm;
        }
        parens.pop();
      }
      c = strm.get();
    }
    istringstream sstrm(s);
    sstrm >> default_value;
    w.SetDefaultValue(default_value);
  }

  c = strm.get();

  { // Read n
    string s;
    while (c != separator) {
      if (c == EOF) {
        strm.clear(std::ios::badbit);
        return strm;
      }
      s += c;
      c = strm.get();
    }
    istringstream sstrm(s);
    sstrm >> n;
  }

  // Read n elements
  for (size_t i = 0; i < n; ++i) {
    // discard separator
    c = strm.get();
    K p;
    W r;

    { // Read key
      stack<int> parens;
      string s;
      while (c != separator || !parens.empty()) {
        if (c == EOF) {
          strm.clear(std::ios::badbit);
          return strm;
        }
        s += c;
        // If parens encountered before separator, they must be matched
        if (c == open_paren) {
          parens.push(1);
        } else if (c == close_paren) {
          // Fail for mismatched parens
          if (parens.empty()) {
            strm.clear(std::ios::failbit);
            return strm;
          }
          parens.pop();
        }
        c = strm.get();
      }
      istringstream sstrm(s);
      sstrm >> p;
    }

    c = strm.get();

    { // Read weight
      stack<int> parens;
      string s;
      while (c != separator || !parens.empty()) {
        if (c == EOF) {
          strm.clear(std::ios::badbit);
          return strm;
        }
        s += c;
        // If parens encountered before separator, they must be matched
        if (c == open_paren) {
          parens.push(1);
        } else if (c == close_paren) {
          // Fail for mismatched parens
          if (parens.empty()) {
            strm.clear(std::ios::failbit);
            return strm;
          }
          parens.pop();
        }
        c = strm.get();
      }
      istringstream sstrm(s);
      sstrm >> r;
    }

    w.Push(p, r);
  }

  if (c != separator) {
    FSTERROR() << " separator expected, not found! ";
    strm.clear(std::ios::badbit);
    return strm;
  }

  c = strm.get();
  if (c != close_paren) {
    FSTERROR() << " is fst_weight_parentheses flag set correcty? ";
    strm.clear(std::ios::badbit);
    return strm;
  }

  return strm;
}



}  // namespace fst

#endif  // FST_LIB_SPARSE_TUPLE_WEIGHT_H__
