// epsnormalize.h

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
// Author: allauzen@google.com (Cyril Allauzen)
//
// \file
// Function that implements epsilon normalization.

#ifndef FST_LIB_EPSNORMALIZE_H__
#define FST_LIB_EPSNORMALIZE_H__

#include <unordered_map>
using std::unordered_map;
using std::unordered_multimap;


#include <fst/factor-weight.h>
#include <fst/invert.h>
#include <fst/arc-map.h>
#include <fst/rmepsilon.h>


namespace fst {

enum EpsNormalizeType {EPS_NORM_INPUT, EPS_NORM_OUTPUT};

// Returns an equivalent FST that is epsilon-normalized. An acceptor is
// epsilon-normalized if it is epsilon-removed. A transducer is input
// epsilon-normalized if additionally if on each path any epsilon input
// label follows all non-epsilon input labels. Output epsilon-normalized
// is defined similarly.
//
// The input FST needs to be functional.
//
// References:
// - Mehryar Mohri. "Generic epsilon-removal and input epsilon-normalization
//   algorithms for weighted transducers", International Journal of Computer
//   Science, 13(1): 129-143, 2002.
template <class Arc>
void EpsNormalize(const Fst<Arc> &ifst, MutableFst<Arc> *ofst,
                      EpsNormalizeType type = EPS_NORM_INPUT) {
  VectorFst< GallicArc<Arc, GALLIC_RIGHT_RESTRICT> > gfst;
  if (type == EPS_NORM_INPUT)
    ArcMap(ifst, &gfst, ToGallicMapper<Arc, GALLIC_RIGHT_RESTRICT>());
  else // type == EPS_NORM_OUTPUT
    ArcMap(InvertFst<Arc>(ifst), &gfst,
           ToGallicMapper<Arc, GALLIC_RIGHT_RESTRICT>());
  RmEpsilon(&gfst);
  FactorWeightFst< GallicArc<Arc, GALLIC_RIGHT_RESTRICT>,
    GallicFactor<typename Arc::Label,
      typename Arc::Weight, GALLIC_RIGHT_RESTRICT> >
    fwfst(gfst);
  ArcMap(fwfst, ofst, FromGallicMapper<Arc, GALLIC_RIGHT_RESTRICT>());
  ofst->SetOutputSymbols(ifst.OutputSymbols());
  if(type == EPS_NORM_OUTPUT)
    Invert(ofst);
}

}  // namespace fst

#endif  // FST_LIB_EPSNORMALIZE_H__
