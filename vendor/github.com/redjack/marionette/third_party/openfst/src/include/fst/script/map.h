
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
// Author: jpr@google.com (Jake Ratkiewicz)

#ifndef FST_SCRIPT_MAP_H_
#define FST_SCRIPT_MAP_H_

#include <fst/script/arg-packs.h>
#include <fst/script/fst-class.h>
#include <fst/script/weight-class.h>
#include <fst/arc-map.h>
#include <fst/state-map.h>

namespace fst {
namespace script {

template <class M>
Fst<typename M::ToArc> *ArcMap(const Fst<typename M::FromArc> &fst,
                            const M &mapper) {
  typedef typename M::ToArc ToArc;
  VectorFst<ToArc> *ofst = new VectorFst<ToArc>;
  ArcMap(fst, ofst, mapper);
  return ofst;
}

template <class M>
Fst<typename M::ToArc> *StateMap(const Fst<typename M::FromArc> &fst,
                                 const M &mapper) {
  typedef typename M::ToArc ToArc;
  VectorFst<ToArc> *ofst = new VectorFst<ToArc>;
  StateMap(fst, ofst, mapper);
  return ofst;
}

enum MapType { ARC_SUM_MAPPER, IDENTITY_MAPPER, INVERT_MAPPER, PLUS_MAPPER,
               QUANTIZE_MAPPER, RMWEIGHT_MAPPER, SUPERFINAL_MAPPER,
               TIMES_MAPPER, TO_LOG_MAPPER, TO_LOG64_MAPPER, TO_STD_MAPPER };

typedef args::Package<const FstClass&, MapType, float,
                      const WeightClass &> MapInnerArgs;
typedef args::WithReturnValue<FstClass*, MapInnerArgs> MapArgs;

template <class Arc>
void Map(MapArgs *args) {
  const Fst<Arc> &ifst = *(args->args.arg1.GetFst<Arc>());
  MapType map_type = args->args.arg2;
  float delta =  args->args.arg3;
  typename Arc::Weight w = *(args->args.arg4.GetWeight<typename Arc::Weight>());

  Fst<Arc> *fst = NULL;
  Fst<LogArc> *lfst = NULL;
  Fst<Log64Arc> *l64fst = NULL;
  Fst<StdArc> *sfst = NULL;
  if (map_type == ARC_SUM_MAPPER) {
    args->retval = new FstClass(*(fst =
        script::StateMap(ifst, ArcSumMapper<Arc>(ifst))));
  } else if (map_type == IDENTITY_MAPPER) {
    args->retval = new FstClass(*(fst =
        script::ArcMap(ifst, IdentityArcMapper<Arc>())));
  } else if (map_type == INVERT_MAPPER) {
    args->retval = new FstClass(*(fst =
        script::ArcMap(ifst, InvertWeightMapper<Arc>())));
  } else if (map_type == PLUS_MAPPER) {
    args->retval = new FstClass(*(fst =
        script::ArcMap(ifst, PlusMapper<Arc>(w))));
  } else if (map_type == QUANTIZE_MAPPER) {
    args->retval = new FstClass(*(fst =
        script::ArcMap(ifst, QuantizeMapper<Arc>(delta))));
  } else if (map_type == RMWEIGHT_MAPPER) {
    args->retval = new FstClass(*(fst =
        script::ArcMap(ifst, RmWeightMapper<Arc>())));
  } else if (map_type == SUPERFINAL_MAPPER) {
    args->retval = new FstClass(*(fst =
        script::ArcMap(ifst, SuperFinalMapper<Arc>())));
  } else if (map_type == TIMES_MAPPER) {
    args->retval = new FstClass(*(fst =
        script::ArcMap(ifst, TimesMapper<Arc>(w))));
  } else if (map_type == TO_LOG_MAPPER) {
    args->retval = new FstClass(*(lfst =
        script::ArcMap(ifst, WeightConvertMapper<Arc, LogArc>())));
  } else if (map_type == TO_LOG64_MAPPER) {
    args->retval = new FstClass(*(l64fst =
        script::ArcMap(ifst, WeightConvertMapper<Arc, Log64Arc>())));
  } else if (map_type == TO_STD_MAPPER) {
    args->retval = new FstClass(*(sfst =
        script::ArcMap(ifst, WeightConvertMapper<Arc, StdArc>())));
  } else {
    FSTERROR() << "Error: unknown/unsupported mapper type: "
               << map_type;
    VectorFst<Arc> *ofst = new VectorFst<Arc>;
    ofst->SetProperties(kError, kError);
    args->retval = new FstClass(*(fst =ofst));
  }
  delete sfst;
  delete l64fst;
  delete lfst;
  delete fst;
}


#ifdef SWIG
%newobject Map;
#endif
FstClass *Map(const FstClass& f, MapType map_type,
         float delta = fst::kDelta,
         const WeightClass &w = fst::script::WeightClass::Zero());

}  // namespace script
}  // namespace fst

#endif  // FST_SCRIPT_MAP_H_
