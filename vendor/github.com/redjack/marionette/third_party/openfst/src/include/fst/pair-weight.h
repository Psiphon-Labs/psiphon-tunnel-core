// pair-weight.h

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
// Author: shumash@google.com (Masha Maria Shugrina)
//
// \file
// Pair weight templated base class for weight classes that
// contain two weights (e.g. Product, Lexicographic)

#ifndef FST_LIB_PAIR_WEIGHT_H_
#define FST_LIB_PAIR_WEIGHT_H_

#include <climits>
#include <stack>
#include <string>

#include <fst/weight.h>


DECLARE_string(fst_weight_parentheses);
DECLARE_string(fst_weight_separator);

namespace fst {

template<class W1, class W2> class PairWeight;
template <class W1, class W2>
istream &operator>>(istream &strm, PairWeight<W1, W2> &w);

template<class W1, class W2>
class PairWeight {
 public:
  friend istream &operator>><W1, W2>(istream&, PairWeight<W1, W2>&);

  typedef PairWeight<typename W1::ReverseWeight,
                     typename W2::ReverseWeight>
  ReverseWeight;

  PairWeight() {}

  PairWeight(const PairWeight& w) : value1_(w.value1_), value2_(w.value2_) {}

  PairWeight(W1 w1, W2 w2) : value1_(w1), value2_(w2) {}

  static const PairWeight<W1, W2> &Zero() {
    static const PairWeight<W1, W2> zero(W1::Zero(), W2::Zero());
    return zero;
  }

  static const PairWeight<W1, W2> &One() {
    static const PairWeight<W1, W2> one(W1::One(), W2::One());
    return one;
  }

  static const PairWeight<W1, W2> &NoWeight() {
    static const PairWeight<W1, W2> no_weight(W1::NoWeight(), W2::NoWeight());
    return no_weight;
  }

  istream &Read(istream &strm) {
    value1_.Read(strm);
    return value2_.Read(strm);
  }

  ostream &Write(ostream &strm) const {
    value1_.Write(strm);
    return value2_.Write(strm);
  }

  PairWeight<W1, W2> &operator=(const PairWeight<W1, W2> &w) {
    value1_ = w.Value1();
    value2_ = w.Value2();
    return *this;
  }

  bool Member() const { return value1_.Member() && value2_.Member(); }

  size_t Hash() const {
    size_t h1 = value1_.Hash();
    size_t h2 = value2_.Hash();
    const int lshift = 5;
    const int rshift = CHAR_BIT * sizeof(size_t) - 5;
    return h1 << lshift ^ h1 >> rshift ^ h2;
  }

  PairWeight<W1, W2> Quantize(float delta = kDelta) const {
    return PairWeight<W1, W2>(value1_.Quantize(delta),
                                 value2_.Quantize(delta));
  }

  ReverseWeight Reverse() const {
    return ReverseWeight(value1_.Reverse(), value2_.Reverse());
  }

  const W1& Value1() const { return value1_; }

  const W2& Value2() const { return value2_; }

 protected:
  void SetValue1(const W1 &w) { value1_ = w; }
  void SetValue2(const W2 &w) { value2_ = w; }

  // Reads PairWeight when there are not parentheses around pair terms
  inline static istream &ReadNoParen(
      istream &strm, PairWeight<W1, W2>& w, char separator) {
    int c;
    do {
      c = strm.get();
    } while (isspace(c));

    string s1;
    while (c != separator) {
      if (c == EOF) {
        strm.clear(std::ios::badbit);
        return strm;
      }
      s1 += c;
      c = strm.get();
    }
    istringstream strm1(s1);
    W1 w1 = W1::Zero();
    strm1 >> w1;

    // read second element
    W2 w2 = W2::Zero();
    strm >> w2;

    w = PairWeight<W1, W2>(w1, w2);
    return strm;
  }

  // Reads PairWeight when there are parentheses around pair terms
  inline static istream &ReadWithParen(
      istream &strm, PairWeight<W1, W2>& w,
      char separator, char open_paren, char close_paren) {
    int c;
    do {
      c = strm.get();
    } while (isspace(c));
    if (c != open_paren) {
      FSTERROR() << " is fst_weight_parentheses flag set correcty? ";
      strm.clear(std::ios::failbit);
      return strm;
    }
    c = strm.get();

    // read first element
    stack<int> parens;
    string s1;
    while (c != separator || !parens.empty()) {
      if (c == EOF) {
        strm.clear(std::ios::badbit);
        return strm;
      }
      s1 += c;
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
    istringstream strm1(s1);
    W1 w1 = W1::Zero();
    strm1 >> w1;

    // read second element
    string s2;
    c = strm.get();
    while (c != EOF) {
      s2 += c;
      c = strm.get();
    }
    if (s2.empty() || (s2[s2.size() - 1] != close_paren)) {
      FSTERROR() << " is fst_weight_parentheses flag set correcty? ";
      strm.clear(std::ios::failbit);
      return strm;
    }

    s2.erase(s2.size() - 1, 1);
    istringstream strm2(s2);
    W2 w2 = W2::Zero();
    strm2 >> w2;

    w = PairWeight<W1, W2>(w1, w2);
    return strm;
  }

 private:
  W1 value1_;
  W2 value2_;

};

template <class W1, class W2>
inline bool operator==(const PairWeight<W1, W2> &w,
                       const PairWeight<W1, W2> &v) {
  return w.Value1() == v.Value1() && w.Value2() == v.Value2();
}

template <class W1, class W2>
inline bool operator!=(const PairWeight<W1, W2> &w1,
                       const PairWeight<W1, W2> &w2) {
  return w1.Value1() != w2.Value1() || w1.Value2() != w2.Value2();
}


template <class W1, class W2>
inline bool ApproxEqual(const PairWeight<W1, W2> &w1,
                        const PairWeight<W1, W2> &w2,
                        float delta = kDelta) {
  return ApproxEqual(w1.Value1(), w2.Value1(), delta) &&
      ApproxEqual(w1.Value2(), w2.Value2(), delta);
}

template <class W1, class W2>
inline ostream &operator<<(ostream &strm, const PairWeight<W1, W2> &w) {
  if(FLAGS_fst_weight_separator.size() != 1) {
    FSTERROR() << "FLAGS_fst_weight_separator.size() is not equal to 1";
    strm.clear(std::ios::badbit);
    return strm;
  }
  char separator = FLAGS_fst_weight_separator[0];
  if (FLAGS_fst_weight_parentheses.empty())
    return strm << w.Value1() << separator << w.Value2();

  if (FLAGS_fst_weight_parentheses.size() != 2) {
    FSTERROR() << "FLAGS_fst_weight_parentheses.size() is not equal to 2";
    strm.clear(std::ios::badbit);
    return strm;
  }
  char open_paren = FLAGS_fst_weight_parentheses[0];
  char close_paren = FLAGS_fst_weight_parentheses[1];
  return strm << open_paren << w.Value1() << separator
              << w.Value2() << close_paren ;
}

template <class W1, class W2>
inline istream &operator>>(istream &strm, PairWeight<W1, W2> &w) {
  if(FLAGS_fst_weight_separator.size() != 1) {
    FSTERROR() << "FLAGS_fst_weight_separator.size() is not equal to 1";
    strm.clear(std::ios::badbit);
    return strm;
  }
  char separator = FLAGS_fst_weight_separator[0];
  bool read_parens = !FLAGS_fst_weight_parentheses.empty();
  if (read_parens) {
    if (FLAGS_fst_weight_parentheses.size() != 2) {
      FSTERROR() << "FLAGS_fst_weight_parentheses.size() is not equal to 2";
      strm.clear(std::ios::badbit);
      return strm;
    }
    return PairWeight<W1, W2>::ReadWithParen(
        strm, w, separator, FLAGS_fst_weight_parentheses[0],
        FLAGS_fst_weight_parentheses[1]);
  } else {
    return PairWeight<W1, W2>::ReadNoParen(strm, w, separator);
  }
}

}  // namespace fst

#endif  // FST_LIB_PAIR_WEIGHT_H_
