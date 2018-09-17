// weight.h

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
// General weight set and associated semiring operation definitions.
//
// A semiring is specified by two binary operations Plus and Times and
// two designated elements Zero and One with the following properties:
//   Plus: associative, commutative, and has Zero as its identity.
//   Times: associative and has identity One, distributes w.r.t. Plus, and
//     has Zero as an annihilator:
//          Times(Zero(), a) == Times(a, Zero()) = Zero().
//
//  A left semiring distributes on the left; a right semiring is
//  similarly defined.
//
// A Weight class must have binary functions =Plus= and =Times= and
// static member functions =Zero()= and =One()= and these must form
// (at least) a left or right semiring.
//
// In addition, the following should be defined for a Weight:
//   Member: predicate on set membership.
//   NoWeight: static member function that returns an element that is
//      not a set member; used to signal an error.
//   >>: reads textual representation of a weight.
//   <<: prints textual representation of a weight.
//   Read(istream &strm): reads binary representation of a weight.
//   Write(ostream &strm): writes binary representation of a weight.
//   Hash: maps weight to size_t.
//   ApproxEqual: approximate equality (for inexact weights)
//   Quantize: quantizes wrt delta (for inexact weights)
//   Divide: for all a,b,c s.t. Times(a, b) == c
//     --> b' = Divide(c, a, DIVIDE_LEFT) if a left semiring, b'.Member()
//      and Times(a, b') == c
//     --> a' = Divide(c, b, DIVIDE_RIGHT) if a right semiring, a'.Member()
//      and Times(a', b) == c
//     --> b' = Divide(c, a) = Divide(c, a, DIVIDE_ANY) =
//      Divide(c, a, DIVIDE_LEFT) = Divide(c, a, DIVIDE_RIGHT) if a
//      commutative semiring, b'.Member() and Times(a, b') = Times(b', a) = c
//   ReverseWeight: the type of the corresponding reverse weight.
//     Typically the same type as Weight for a (both left and right) semiring.
//     For the left string semiring, it is the right string semiring.
//   Reverse: a mapping from Weight to ReverseWeight s.t.
//     --> Reverse(Reverse(a)) = a
//     --> Reverse(Plus(a, b)) = Plus(Reverse(a), Reverse(b))
//     --> Reverse(Times(a, b)) = Times(Reverse(b), Reverse(a))
//     Typically the identity mapping in a (both left and right) semiring.
//     In the left string semiring, it maps to the reverse string
//     in the right string semiring.
//   Properties: specifies additional properties that hold:
//      LeftSemiring: indicates weights form a left semiring.
//      RightSemiring: indicates weights form a right semiring.
//      Commutative: for all a,b: Times(a,b) == Times(b,a)
//      Idempotent: for all a: Plus(a, a) == a.
//      Path: for all a, b: Plus(a, b) == a or Plus(a, b) == b.


#ifndef FST_LIB_WEIGHT_H__
#define FST_LIB_WEIGHT_H__

#include <cmath>
#include <cctype>
#include <iostream>
#include <sstream>

#include <fst/compat.h>

#include <fst/util.h>


namespace fst {

//
// CONSTANT DEFINITIONS
//

// A representable float near .001
const float kDelta =                   1.0F/1024.0F;

// For all a,b,c: Times(c, Plus(a,b)) = Plus(Times(c,a), Times(c, b))
const uint64 kLeftSemiring =           0x0000000000000001ULL;

// For all a,b,c: Times(Plus(a,b), c) = Plus(Times(a,c), Times(b, c))
const uint64 kRightSemiring =          0x0000000000000002ULL;

const uint64 kSemiring = kLeftSemiring | kRightSemiring;

// For all a,b: Times(a,b) = Times(b,a)
const uint64 kCommutative =       0x0000000000000004ULL;

// For all a: Plus(a, a) = a
const uint64 kIdempotent =             0x0000000000000008ULL;

// For all a,b: Plus(a,b) = a or Plus(a,b) = b
const uint64 kPath =                   0x0000000000000010ULL;


// Determines direction of division.
enum DivideType { DIVIDE_LEFT,   // left division
                  DIVIDE_RIGHT,  // right division
                  DIVIDE_ANY };  // division in a commutative semiring

// NATURAL ORDER
//
// By definition:
//                 a <= b iff a + b = a
// The natural order is a negative partial order iff the semiring is
// idempotent. It is trivially monotonic for plus. It is left
// (resp. right) monotonic for times iff the semiring is left
// (resp. right) distributive. It is a total order iff the semiring
// has the path property. See Mohri, "Semiring Framework and
// Algorithms for Shortest-Distance Problems", Journal of Automata,
// Languages and Combinatorics 7(3):321-350, 2002. We define the
// strict version of this order below.

template <class W>
class NaturalLess {
 public:
  typedef W Weight;

  NaturalLess() {
    if (!(W::Properties() & kIdempotent)) {
      FSTERROR() << "NaturalLess: Weight type is not idempotent: "
                 << W::Type();
    }
  }

  bool operator()(const W &w1, const W &w2) const {
    return (Plus(w1, w2) == w1) && w1 != w2;
  }
};


// Power is the iterated product for arbitrary semirings such that
// Power(w, 0) is One() for the semiring, and
// Power(w, n) = Times(Power(w, n-1), w)

template <class W>
W Power(W w, size_t n) {
  W result = W::One();
  for (size_t i = 0; i < n; ++i) {
    result = Times(result, w);
  }
  return result;
}

// General weight converter - raises error.
template <class W1, class W2>
struct WeightConvert {
  W2 operator()(W1 w1) const {
    FSTERROR() << "WeightConvert: can't convert weight from \""
               << W1::Type() << "\" to \"" << W2::Type();
    return W2::NoWeight();
  }
};

// Specialized weight converter to self.
template <class W>
struct WeightConvert<W, W> {
  W operator()(W w) const { return w; }
};

}  // namespace fst

#endif  // FST_LIB_WEIGHT_H__
