
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

#ifndef FST_SCRIPT_ARCSORT_H_
#define FST_SCRIPT_ARCSORT_H_

#include <fst/arcsort.h>
#include <fst/script/arg-packs.h>
#include <fst/script/fst-class.h>

namespace fst {
namespace script {

enum ArcSortType { ILABEL_COMPARE, OLABEL_COMPARE };

typedef args::Package<MutableFstClass*, const ArcSortType> ArcSortArgs;

template<class Arc>
void ArcSort(ArcSortArgs *args) {
  MutableFst<Arc> *fst = args->arg1->GetMutableFst<Arc>();

  if (args->arg2 == ILABEL_COMPARE) {
    ILabelCompare<Arc> icomp;
    ArcSort(fst, icomp);
  } else {       // OLABEL_COMPARE
    OLabelCompare<Arc> ocomp;
    ArcSort(fst, ocomp);
  }
}

void ArcSort(MutableFstClass *ofst, ArcSortType sort_type);

}  // namespace script
}  // namespace fst

#endif  // FST_SCRIPT_ARCSORT_H_
