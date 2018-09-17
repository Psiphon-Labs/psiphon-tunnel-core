
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

#ifndef FST_SCRIPT_DIFFERENCE_H_
#define FST_SCRIPT_DIFFERENCE_H_

#include <fst/script/arg-packs.h>
#include <fst/script/fst-class.h>
#include <fst/script/compose.h>  // for ComposeFilter
#include <fst/difference.h>

namespace fst {
namespace script {

typedef args::Package<const FstClass&, const FstClass&,
                      MutableFstClass*, ComposeFilter> DifferenceArgs1;

template<class Arc>
void Difference(DifferenceArgs1 *args) {
  const Fst<Arc> &ifst1 = *(args->arg1.GetFst<Arc>());
  const Fst<Arc> &ifst2 = *(args->arg2.GetFst<Arc>());
  MutableFst<Arc> *ofst = args->arg3->GetMutableFst<Arc>();

  Difference(ifst1, ifst2, ofst, args->arg4);
}

typedef args::Package<const FstClass&, const FstClass&,
                      MutableFstClass*, const ComposeOptions &> DifferenceArgs2;

template<class Arc>
void Difference(DifferenceArgs2  *args) {
  const Fst<Arc> &ifst1 = *(args->arg1.GetFst<Arc>());
  const Fst<Arc> &ifst2 = *(args->arg2.GetFst<Arc>());
  MutableFst<Arc> *ofst = args->arg3->GetMutableFst<Arc>();

  Difference(ifst1, ifst2, ofst, args->arg4);
}


void Difference(const FstClass &ifst1, const FstClass &ifst2,
                MutableFstClass *ofst,
                ComposeFilter compose_filter);

void Difference(const FstClass &ifst1, const FstClass &ifst2,
                MutableFstClass *ofst,
                const ComposeOptions &opts = fst::script::ComposeOptions());


}  // namespace script
}  // namespace fst



#endif  // FST_SCRIPT_DIFFERENCE_H_
