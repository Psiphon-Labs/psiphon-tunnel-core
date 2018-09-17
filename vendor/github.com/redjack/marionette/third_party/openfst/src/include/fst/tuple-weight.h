// tuple-weight.h

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
// Author: allauzen@google (Cyril Allauzen)
//
// \file
// Tuple weight set operation definitions.

#ifndef FST_LIB_TUPLE_WEIGHT_H__
#define FST_LIB_TUPLE_WEIGHT_H__

#include <string>
#include <vector>
using std::vector;

#include <fst/weight.h>


DECLARE_string(fst_weight_parentheses);
DECLARE_string(fst_weight_separator);

namespace fst {

template<class W, unsigned int n> class TupleWeight;
template <class W, unsigned int n>
istream &operator>>(istream &strm, TupleWeight<W, n> &w);

// n-tuple weight, element of the n-th catersian power of W
template <class W, unsigned int n>
class TupleWeight {
 public:
  typedef TupleWeight<typename W::ReverseWeight, n> ReverseWeight;

  TupleWeight() {}

  TupleWeight(const TupleWeight &w) {
    for (size_t i = 0; i < n; ++i)
      values_[i] = w.values_[i];
  }

  template <class Iterator>
  TupleWeight(Iterator begin, Iterator end) {
    for (Iterator iter = begin; iter != end; ++iter)
      values_[iter - begin] = *iter;
  }

  TupleWeight(const W &w) {
    for (size_t i = 0; i < n; ++i)
      values_[i] = w;
  }

  static const TupleWeight<W, n> &Zero() {
    static const TupleWeight<W, n> zero(W::Zero());
    return zero;
  }

  static const TupleWeight<W, n> &One() {
    static const TupleWeight<W, n> one(W::One());
    return one;
  }

  static const TupleWeight<W, n> &NoWeight() {
    static const TupleWeight<W, n> no_weight(W::NoWeight());
    return no_weight;
  }

  static unsigned int Length() {
    return n;
  }

  istream &Read(istream &strm) {
    for (size_t i = 0; i < n; ++i)
      values_[i].Read(strm);
    return strm;
  }

  ostream &Write(ostream &strm) const {
    for (size_t i = 0; i < n; ++i)
      values_[i].Write(strm);
    return strm;
  }

  TupleWeight<W, n> &operator=(const TupleWeight<W, n> &w) {
    for (size_t i = 0; i < n; ++i)
      values_[i] = w.values_[i];
    return *this;
  }

  bool Member() const {
    bool member = true;
    for (size_t i = 0; i < n; ++i)
      member = member && values_[i].Member();
    return member;
  }

  size_t Hash() const {
    uint64 hash = 0;
    for (size_t i = 0; i < n; ++i)
      hash = 5 * hash + values_[i].Hash();
    return size_t(hash);
  }

  TupleWeight<W, n> Quantize(float delta = kDelta) const {
    TupleWeight<W, n> w;
    for (size_t i = 0; i < n; ++i)
      w.values_[i] = values_[i].Quantize(delta);
    return w;
  }

  ReverseWeight Reverse() const {
    TupleWeight<W, n> w;
    for (size_t i = 0; i < n; ++i)
      w.values_[i] = values_[i].Reverse();
    return w;
  }

  const W& Value(size_t i) const { return values_[i]; }

  void SetValue(size_t i, const W &w) { values_[i] = w; }

 protected:
  // Reads TupleWeight when there are no parentheses around tuple terms
  inline static istream &ReadNoParen(istream &strm,
                                     TupleWeight<W, n> &w,
                                     char separator) {
    int c;
    do {
      c = strm.get();
    } while (isspace(c));

    for (size_t i = 0; i < n - 1; ++i) {
      string s;
      if (i)
        c = strm.get();
      while (c != separator) {
        if (c == EOF) {
          strm.clear(std::ios::badbit);
          return strm;
        }
        s += c;
        c = strm.get();
      }
      // read (i+1)-th element
      istringstream sstrm(s);
      W r = W::Zero();
      sstrm >> r;
      w.SetValue(i, r);
    }

    // read n-th element
    W r = W::Zero();
    strm >> r;
    w.SetValue(n - 1, r);

    return strm;
  }

  // Reads TupleWeight when there are parentheses around tuple terms
  inline static istream &ReadWithParen(istream &strm,
                                       TupleWeight<W, n> &w,
                                       char separator,
                                       char open_paren,
                                       char close_paren) {
    int c;
    do {
      c = strm.get();
    } while (isspace(c));

    if (c != open_paren) {
      FSTERROR() << " is fst_weight_parentheses flag set correcty? ";
      strm.clear(std::ios::badbit);
      return strm;
    }

    for (size_t i = 0; i < n - 1; ++i) {
      // read (i+1)-th element
      stack<int> parens;
      string s;
      c = strm.get();
      while (c != separator || !parens.empty()) {
        if (c == EOF) {
          strm.clear(std::ios::badbit);
          return strm;
        }
        s += c;
        // if parens encountered before separator, they must be matched
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
      W r = W::Zero();
      sstrm >> r;
      w.SetValue(i, r);
    }

    // read n-th element
    string s;
    c = strm.get();
    while (c != EOF) {
      s += c;
      c = strm.get();
    }
    if (s.empty() || *s.rbegin() != close_paren) {
      FSTERROR() << " is fst_weight_parentheses flag set correcty? ";
      strm.clear(std::ios::failbit);
      return strm;
    }
    s.erase(s.size() - 1, 1);
    istringstream sstrm(s);
    W r = W::Zero();
    sstrm >> r;
    w.SetValue(n - 1, r);

    return strm;
  }


 private:
  W values_[n];

  friend istream &operator>><W, n>(istream&, TupleWeight<W, n>&);
};

template <class W, unsigned int n>
inline bool operator==(const TupleWeight<W, n> &w1,
                       const TupleWeight<W, n> &w2) {
  bool equal = true;
  for (size_t i = 0; i < n; ++i)
    equal = equal && (w1.Value(i) == w2.Value(i));
  return equal;
}

template <class W, unsigned int n>
inline bool operator!=(const TupleWeight<W, n> &w1,
                       const TupleWeight<W, n> &w2) {
  bool not_equal = false;
  for (size_t i = 0; (i < n) && !not_equal; ++i)
    not_equal = not_equal || (w1.Value(i) != w2.Value(i));
  return not_equal;
}

template <class W, unsigned int n>
inline bool ApproxEqual(const TupleWeight<W, n> &w1,
                        const TupleWeight<W, n> &w2,
                        float delta = kDelta) {
  bool approx_equal = true;
  for (size_t i = 0; i < n; ++i)
    approx_equal = approx_equal &&
        ApproxEqual(w1.Value(i), w2.Value(i), delta);
  return approx_equal;
}

template <class W, unsigned int n>
inline ostream &operator<<(ostream &strm, const TupleWeight<W, n> &w) {
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
  for (size_t i  = 0; i < n; ++i) {
    if(i)
      strm << separator;
    strm << w.Value(i);
  }
  if (write_parens)
    strm << FLAGS_fst_weight_parentheses[1];

  return strm;
}

template <class W, unsigned int n>
inline istream &operator>>(istream &strm, TupleWeight<W, n> &w) {
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
    return TupleWeight<W, n>::ReadWithParen(
        strm, w, separator, FLAGS_fst_weight_parentheses[0],
        FLAGS_fst_weight_parentheses[1]);
  } else {
    return TupleWeight<W, n>::ReadNoParen(strm, w, separator);
  }
}



}  // namespace fst

#endif  // FST_LIB_TUPLE_WEIGHT_H__
