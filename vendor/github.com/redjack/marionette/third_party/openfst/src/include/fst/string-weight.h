// string-weight.h

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
// String weight set and associated semiring operation definitions.

#ifndef FST_LIB_STRING_WEIGHT_H__
#define FST_LIB_STRING_WEIGHT_H__

#include <list>
#include <string>

#include <fst/product-weight.h>
#include <fst/weight.h>


namespace fst {

const int kStringInfinity = -1;      // Label for the infinite string
const int kStringBad = -2;           // Label for a non-string
const char kStringSeparator = '_';   // Label separator in strings

// Determines whether to use left or right string semiring.  Includes
// 'restricted' versions that signal an error if proper prefixes
// (suffixes) would otherwise be returned by Plus, useful with various
// algorithms that require functional transducer input with the
// string semirings.
enum StringType { STRING_LEFT = 0, STRING_RIGHT = 1 ,
                  STRING_LEFT_RESTRICT = 2, STRING_RIGHT_RESTRICT = 3,
};

#define REVERSE_STRING_TYPE(S)                                  \
   ((S) == STRING_LEFT ? STRING_RIGHT :                         \
    ((S) == STRING_RIGHT ? STRING_LEFT :                        \
     ((S) == STRING_LEFT_RESTRICT ? STRING_RIGHT_RESTRICT :     \
      STRING_LEFT_RESTRICT)))

template <typename L, StringType S = STRING_LEFT>
class StringWeight;

template <typename L, StringType S = STRING_LEFT>
class StringWeightIterator;

template <typename L, StringType S = STRING_LEFT>
class StringWeightReverseIterator;

template <typename L, StringType S>
bool operator==(const StringWeight<L, S> &,  const StringWeight<L, S> &);


// String semiring: (longest_common_prefix/suffix, ., Infinity, Epsilon)
template <typename L, StringType S>
class StringWeight {
 public:
  typedef L Label;
  typedef StringWeight<L, REVERSE_STRING_TYPE(S)> ReverseWeight;

  friend class StringWeightIterator<L, S>;
  friend class StringWeightReverseIterator<L, S>;
  friend bool operator==<>(const StringWeight<L, S> &,
                           const StringWeight<L, S> &);

  StringWeight() { Init(); }

  template <typename Iter>
  StringWeight(const Iter &begin, const Iter &end) {
    Init();
    for (Iter iter = begin; iter != end; ++iter)
      PushBack(*iter);
  }

  explicit StringWeight(L l) { Init(); PushBack(l); }

  static const StringWeight<L, S> &Zero() {
    static const StringWeight<L, S> zero(kStringInfinity);
    return zero;
  }

  static const StringWeight<L, S> &One() {
    static const StringWeight<L, S> one;
    return one;
  }

  static const StringWeight<L, S> &NoWeight() {
    static const StringWeight<L, S> no_weight(kStringBad);
    return no_weight;
  }

  static const string &Type() {
    static const string type =
        S == STRING_LEFT ? "string" :
        (S == STRING_RIGHT ? "right_string" :
         (S == STRING_LEFT_RESTRICT ? "restricted_string" :
          "right_restricted_string"));
    return type;
  }

  bool Member() const;

  istream &Read(istream &strm);

  ostream &Write(ostream &strm) const;

  size_t Hash() const;

  StringWeight<L, S> Quantize(float delta = kDelta) const {
    return *this;
  }

  ReverseWeight Reverse() const;

  static uint64 Properties() {
    return (S == STRING_LEFT ||
            S == STRING_LEFT_RESTRICT ?
            kLeftSemiring : kRightSemiring) | kIdempotent;
  }

  // NB: This needs to be uncommented only if default fails for this impl.
  // StringWeight<L, S> &operator=(const StringWeight<L, S> &w);

  // These operations combined with the StringWeightIterator and
  // StringWeightReverseIterator provide the access and mutation of
  // the string internal elements.

  // Common initializer among constructors.
  void Init() { first_ = 0; }

  // Clear existing StringWeight.
  void Clear() { first_ = 0; rest_.clear(); }

  size_t Size() const { return first_ ? rest_.size() + 1 : 0; }

  void PushFront(L l) {
    if (first_)
      rest_.push_front(first_);
    first_ = l;
  }

  void PushBack(L l) {
    if (!first_)
      first_ = l;
    else
      rest_.push_back(l);
  }

 private:
  L first_;         // first label in string (0 if empty)
  list<L> rest_;    // remaining labels in string
};


// Traverses string in forward direction.
template <typename L, StringType S>
class StringWeightIterator {
 public:
  explicit StringWeightIterator(const StringWeight<L, S>& w)
      : first_(w.first_), rest_(w.rest_), init_(true),
        iter_(rest_.begin()) {}

  bool Done() const {
    if (init_) return first_ == 0;
    else return iter_ == rest_.end();
  }

  const L& Value() const { return init_ ? first_ : *iter_; }

  void Next() {
    if (init_) init_ = false;
    else  ++iter_;
  }

  void Reset() {
    init_ = true;
    iter_ = rest_.begin();
  }

 private:
  const L &first_;
  const list<L> &rest_;
  bool init_;   // in the initialized state?
  typename list<L>::const_iterator iter_;

  DISALLOW_COPY_AND_ASSIGN(StringWeightIterator);
};


// Traverses string in backward direction.
template <typename L, StringType S>
class StringWeightReverseIterator {
 public:
  explicit StringWeightReverseIterator(const StringWeight<L, S>& w)
      : first_(w.first_), rest_(w.rest_), fin_(first_ == 0),
        iter_(rest_.rbegin()) {}

  bool Done() const { return fin_; }

  const L& Value() const { return iter_ == rest_.rend() ? first_ : *iter_; }

  void Next() {
    if (iter_ == rest_.rend()) fin_ = true;
    else  ++iter_;
  }

  void Reset() {
    fin_ = false;
    iter_ = rest_.rbegin();
  }

 private:
  const L &first_;
  const list<L> &rest_;
  bool fin_;   // in the final state?
  typename list<L>::const_reverse_iterator iter_;

  DISALLOW_COPY_AND_ASSIGN(StringWeightReverseIterator);
};


// StringWeight member functions follow that require
// StringWeightIterator or StringWeightReverseIterator.

template <typename L, StringType S>
inline istream &StringWeight<L, S>::Read(istream &strm) {
  Clear();
  int32 size;
  ReadType(strm, &size);
  for (int i = 0; i < size; ++i) {
    L label;
    ReadType(strm, &label);
    PushBack(label);
  }
  return strm;
}

template <typename L, StringType S>
inline ostream &StringWeight<L, S>::Write(ostream &strm) const {
  int32 size =  Size();
  WriteType(strm, size);
  for (StringWeightIterator<L, S> iter(*this); !iter.Done(); iter.Next()) {
    L label = iter.Value();
    WriteType(strm, label);
  }
  return strm;
}

template <typename L, StringType S>
inline bool StringWeight<L, S>::Member() const {
  if (Size() != 1)
    return true;
  StringWeightIterator<L, S> iter(*this);
  return iter.Value() != kStringBad;
}

template <typename L, StringType S>
inline typename StringWeight<L, S>::ReverseWeight
StringWeight<L, S>::Reverse() const {
  ReverseWeight rw;
  for (StringWeightIterator<L, S> iter(*this); !iter.Done(); iter.Next())
    rw.PushFront(iter.Value());
  return rw;
}

template <typename L, StringType S>
inline size_t StringWeight<L, S>::Hash() const {
  size_t h = 0;
  for (StringWeightIterator<L, S> iter(*this); !iter.Done(); iter.Next())
    h ^= h<<1 ^ iter.Value();
  return h;
}

// NB: This needs to be uncommented only if default fails for this the impl.
//
// template <typename L, StringType S>
// inline StringWeight<L, S>
// &StringWeight<L, S>::operator=(const StringWeight<L, S> &w) {
//   if (this != &w) {
//     Clear();
//     for (StringWeightIterator<L, S> iter(w); !iter.Done(); iter.Next())
//       PushBack(iter.Value());
//   }
//   return *this;
// }

template <typename L, StringType S>
inline bool operator==(const StringWeight<L, S> &w1,
                       const StringWeight<L, S> &w2) {
  if (w1.Size() != w2.Size())
    return false;

  StringWeightIterator<L, S> iter1(w1);
  StringWeightIterator<L, S> iter2(w2);

  for (; !iter1.Done() ; iter1.Next(), iter2.Next())
    if (iter1.Value() != iter2.Value())
      return false;

  return true;
}

template <typename L, StringType S>
inline bool operator!=(const StringWeight<L, S> &w1,
                       const StringWeight<L, S> &w2) {
  return !(w1 == w2);
}

template <typename L, StringType S>
inline bool ApproxEqual(const StringWeight<L, S> &w1,
                        const StringWeight<L, S> &w2,
                        float delta = kDelta) {
  return w1 == w2;
}

template <typename L, StringType S>
inline ostream &operator<<(ostream &strm, const StringWeight<L, S> &w) {
  StringWeightIterator<L, S> iter(w);
  if (iter.Done())
    return strm << "Epsilon";
  else if (iter.Value() == kStringInfinity)
    return strm << "Infinity";
  else if (iter.Value() == kStringBad)
    return strm << "BadString";
  else
    for (size_t i = 0; !iter.Done(); ++i, iter.Next()) {
      if (i > 0)
        strm << kStringSeparator;
      strm << iter.Value();
    }
  return strm;
}

template <typename L, StringType S>
inline istream &operator>>(istream &strm, StringWeight<L, S> &w) {
  string s;
  strm >> s;
  if (s == "Infinity") {
    w = StringWeight<L, S>::Zero();
  } else if (s == "Epsilon") {
    w = StringWeight<L, S>::One();
  } else {
    w.Clear();
    char *p = 0;
    for (const char *cs = s.c_str(); !p || *p != '\0'; cs = p + 1) {
      int l = strtoll(cs, &p, 10);
      if (p == cs || (*p != 0 && *p != kStringSeparator)) {
        strm.clear(std::ios::badbit);
        break;
      }
      w.PushBack(l);
    }
  }
  return strm;
}


// Default is for the restricted left and right semirings.  String
// equality is required (for non-Zero() input. The restriction
// is used in e.g. Determinize to ensure functional input.
template <typename L, StringType S>  inline StringWeight<L, S>
Plus(const StringWeight<L, S> &w1,
     const StringWeight<L, S> &w2) {
  if (!w1.Member() || !w2.Member())
    return StringWeight<L, S>::NoWeight();
  if (w1 == StringWeight<L, S>::Zero())
    return w2;
  if (w2 == StringWeight<L, S>::Zero())
    return w1;

  if (w1 != w2) {
    FSTERROR() << "StringWeight::Plus: unequal arguments "
               << "(non-functional FST?)"
               << " w1 = " << w1
               << " w2 = " << w2;
    return StringWeight<L, S>::NoWeight();
  }

  return w1;
}


// Longest common prefix for left string semiring.
template <typename L>  inline StringWeight<L, STRING_LEFT>
Plus(const StringWeight<L, STRING_LEFT> &w1,
     const StringWeight<L, STRING_LEFT> &w2) {
  if (!w1.Member() || !w2.Member())
    return StringWeight<L, STRING_LEFT>::NoWeight();
  if (w1 == StringWeight<L, STRING_LEFT>::Zero())
    return w2;
  if (w2 == StringWeight<L, STRING_LEFT>::Zero())
    return w1;

  StringWeight<L, STRING_LEFT> sum;
  StringWeightIterator<L, STRING_LEFT> iter1(w1);
  StringWeightIterator<L, STRING_LEFT> iter2(w2);
  for (; !iter1.Done() && !iter2.Done() && iter1.Value() == iter2.Value();
       iter1.Next(), iter2.Next())
    sum.PushBack(iter1.Value());
  return sum;
}


// Longest common suffix for right string semiring.
template <typename L>  inline StringWeight<L, STRING_RIGHT>
Plus(const StringWeight<L, STRING_RIGHT> &w1,
     const StringWeight<L, STRING_RIGHT> &w2) {
  if (!w1.Member() || !w2.Member())
    return StringWeight<L, STRING_RIGHT>::NoWeight();
  if (w1 == StringWeight<L, STRING_RIGHT>::Zero())
    return w2;
  if (w2 == StringWeight<L, STRING_RIGHT>::Zero())
    return w1;

  StringWeight<L, STRING_RIGHT> sum;
  StringWeightReverseIterator<L, STRING_RIGHT> iter1(w1);
  StringWeightReverseIterator<L, STRING_RIGHT> iter2(w2);
  for (; !iter1.Done() && !iter2.Done() && iter1.Value() == iter2.Value();
       iter1.Next(), iter2.Next())
    sum.PushFront(iter1.Value());
  return sum;
}


template <typename L, StringType S>
inline StringWeight<L, S> Times(const StringWeight<L, S> &w1,
                             const StringWeight<L, S> &w2) {
  if (!w1.Member() || !w2.Member())
    return StringWeight<L, S>::NoWeight();
  if (w1 == StringWeight<L, S>::Zero() || w2 == StringWeight<L, S>::Zero())
    return StringWeight<L, S>::Zero();

  StringWeight<L, S> prod(w1);
  for (StringWeightIterator<L, S> iter(w2); !iter.Done(); iter.Next())
    prod.PushBack(iter.Value());

  return prod;
}


// Default is for left division in the left string semirings.
template <typename L, StringType S> inline StringWeight<L, S>
Divide(const StringWeight<L, S> &w1,
       const StringWeight<L, S> &w2,
       DivideType typ) {

  if (typ != DIVIDE_LEFT) {
    FSTERROR() << "StringWeight::Divide: only left division is defined "
               << "for the " << StringWeight<L, S>::Type() << " semiring";
    return StringWeight<L, S>::NoWeight();
  }

  if (!w1.Member() || !w2.Member())
    return StringWeight<L, S>::NoWeight();

  if (w2 == StringWeight<L, S>::Zero())
    return StringWeight<L, S>(kStringBad);
  else if (w1 == StringWeight<L, S>::Zero())
    return StringWeight<L, S>::Zero();

  StringWeight<L, S> div;
  StringWeightIterator<L, S> iter(w1);
  for (int i = 0; !iter.Done(); iter.Next(), ++i) {
    if (i >= w2.Size())
      div.PushBack(iter.Value());
  }
  return div;
}

// Right division in the right string semiring.
template <typename L> inline StringWeight<L, STRING_RIGHT>
Divide(const StringWeight<L, STRING_RIGHT> &w1,
       const StringWeight<L, STRING_RIGHT> &w2,
       DivideType typ) {
  return DivideRight(w1, w2, typ);
}

// Right division in the right restricted string semiring.
template <typename L> inline StringWeight<L, STRING_RIGHT_RESTRICT>
Divide(const StringWeight<L, STRING_RIGHT_RESTRICT> &w1,
       const StringWeight<L, STRING_RIGHT_RESTRICT> &w2,
       DivideType typ) {
  return DivideRight(w1, w2, typ);
}

// Right division in a right string semiring.
template <typename L, StringType S> inline StringWeight<L, S>
DivideRight(const StringWeight<L, S> &w1,
            const StringWeight<L, S> &w2,
            DivideType typ) {
  if (typ != DIVIDE_RIGHT) {
    FSTERROR() << "StringWeight::Divide: only right division is defined "
               << "for a right semiring";
    return StringWeight<L, S>::NoWeight();
  }

  if (!w1.Member() || !w2.Member())
    return StringWeight<L, S>::NoWeight();

  if (w2 == StringWeight<L, S>::Zero())
    return StringWeight<L, S>(kStringBad);
  else if (w1 == StringWeight<L, S>::Zero())
    return StringWeight<L, S>::Zero();

  StringWeight<L, S> div;
  StringWeightReverseIterator<L, S> iter(w1);
  for (int i = 0; !iter.Done(); iter.Next(), ++i) {
    if (i >= w2.Size())
      div.PushFront(iter.Value());
  }
  return div;
}

// Determines whether to use left or right gallic semiring.  Includes
// 'restricted' versions that signal an error if proper string
// prefixes (suffixes) would otherwise be returned by string Plus,
// useful with various algorithms that require functional transducer
// input. Also includes 'min' versions that change the Plus to keep
// only the lowest W weight string.
enum GallicType { GALLIC_LEFT = 0, GALLIC_RIGHT = 1 ,
                  GALLIC_LEFT_RESTRICT = 2, GALLIC_RIGHT_RESTRICT = 3,
                  GALLIC_LEFT_MIN = 4, GALLIC_RIGHT_MIN = 5,
};

#define GALLIC_STRING_TYPE(G)                                   \
   ((G) == GALLIC_LEFT ? STRING_LEFT :                          \
    ((G) == GALLIC_RIGHT ? STRING_RIGHT :                       \
     (((G) == GALLIC_LEFT_RESTRICT || (G) == GALLIC_LEFT_MIN) ? \
      STRING_LEFT_RESTRICT : STRING_RIGHT_RESTRICT)))

#define REVERSE_GALLIC_TYPE(G)                                  \
   ((G) == GALLIC_LEFT ? GALLIC_RIGHT :                         \
    ((G) == GALLIC_RIGHT ? GALLIC_LEFT :                        \
     ((G) == GALLIC_LEFT_RESTRICT ? GALLIC_RIGHT_RESTRICT :     \
      ((G) == GALLIC_RIGHT_RESTRICT ? GALLIC_LEFT_RESTRICT :    \
       ((G) == GALLIC_LEFT_MIN ? GALLIC_RIGHT_MIN :             \
        GALLIC_LEFT_MIN)))))

// Product of string weight and an arbitray weight.
template <class L, class W, GallicType G = GALLIC_LEFT>
struct GallicWeight
    : public ProductWeight<StringWeight<L, GALLIC_STRING_TYPE(G)>, W> {
  typedef StringWeight<L, GALLIC_STRING_TYPE(G)> SW;
  typedef GallicWeight<L, typename W::ReverseWeight, REVERSE_GALLIC_TYPE(G)>
  ReverseWeight;

  using ProductWeight<SW, W>::Zero;
  using ProductWeight<SW, W>::One;
  using ProductWeight<SW, W>::NoWeight;
  using ProductWeight<SW, W>::Quantize;
  using ProductWeight<SW, W>::Reverse;

  GallicWeight() {}

  GallicWeight(SW w1, W w2)
      : ProductWeight<SW, W>(w1, w2) {}

  explicit GallicWeight(const string &s, int *nread = 0)
      : ProductWeight<SW, W>(s, nread) {}

  static const GallicWeight<L, W, G> &Zero() {
    static const GallicWeight<L, W, G> zero(ProductWeight<SW, W>::Zero());
    return zero;
  }

  static const GallicWeight<L, W, G> &One() {
    static const GallicWeight<L, W, G> one(ProductWeight<SW, W>::One());
    return one;
  }

  static const GallicWeight<L, W, G> &NoWeight() {
    static const GallicWeight<L, W, G> no_weight(
        ProductWeight<SW, W>::NoWeight());
    return no_weight;
  }

  static const string &Type() {
    static const string type =
        G == GALLIC_LEFT ? "gallic" :
        (G == GALLIC_RIGHT ? "right_gallic" :
         (G == GALLIC_LEFT_RESTRICT ? "restricted_gallic" :
          (G == GALLIC_RIGHT_RESTRICT ? "right_restricted_gallic" :
           (G == GALLIC_LEFT_MIN ? "min_gallic" :
            "right_min_gallic"))));
    return type;
  }

  GallicWeight<L, W, G> Quantize(float delta = kDelta) const {
    return ProductWeight<SW, W>::Quantize(delta);
  }

  ReverseWeight Reverse() const { return ProductWeight<SW, W>::Reverse(); }

  GallicWeight(const ProductWeight<SW, W> &w) : ProductWeight<SW, W>(w) {}
};

// Default plus
template <class L, class W, GallicType G>
inline GallicWeight<L, W, G> Plus(const GallicWeight<L, W, G> &w,
                                   const GallicWeight<L, W, G> &v) {
  return GallicWeight<L, W, G>(Plus(w.Value1(), v.Value1()),
                               Plus(w.Value2(), v.Value2()));
}

// Left min gallic plus
template <class L, class W>
inline GallicWeight<L, W, GALLIC_LEFT_MIN>
Plus(const GallicWeight<L, W, GALLIC_LEFT_MIN> &w1,
     const GallicWeight<L, W, GALLIC_LEFT_MIN> &w2) {
  NaturalLess<W> less;
  return less(w1.Value2(), w2.Value2()) ? w1 : w2;
}

// Right min gallic plus
template <class L, class W>
inline GallicWeight<L, W, GALLIC_RIGHT_MIN>
Plus(const GallicWeight<L, W, GALLIC_RIGHT_MIN> &w1,
     const GallicWeight<L, W, GALLIC_RIGHT_MIN> &w2) {
  NaturalLess<W> less;
  return less(w1.Value2(), w2.Value2()) ? w1 : w2;
}

template <class L, class W, GallicType G>
inline GallicWeight<L, W, G> Times(const GallicWeight<L, W, G> &w,
                                   const GallicWeight<L, W, G> &v) {
  return GallicWeight<L, W, G>(Times(w.Value1(), v.Value1()),
                               Times(w.Value2(), v.Value2()));
}

template <class L, class W, GallicType G>
inline GallicWeight<L, W, G> Divide(const GallicWeight<L, W, G> &w,
                                    const GallicWeight<L, W, G> &v,
                                    DivideType typ = DIVIDE_ANY) {
  return GallicWeight<L, W, G>(Divide(w.Value1(), v.Value1(), typ),
                               Divide(w.Value2(), v.Value2(), typ));
}

}  // namespace fst

#endif  // FST_LIB_STRING_WEIGHT_H__
