
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

#ifndef FST_SCRIPT_EPSNORMALIZE_H_
#define FST_SCRIPT_EPSNORMALIZE_H_

#include <fst/script/arg-packs.h>
#include <fst/script/fst-class.h>
#include <fst/epsnormalize.h>

namespace fst {
namespace script {

typedef args::Package<const FstClass&, MutableFstClass*,
                      EpsNormalizeType> EpsNormalizeArgs;

template<class Arc>
void EpsNormalize(EpsNormalizeArgs  *args) {
  const Fst<Arc> &ifst = *(args->arg1.GetFst<Arc>());
  MutableFst<Arc> *ofst = args->arg2->GetMutableFst<Arc>();

  EpsNormalize(ifst, ofst, args->arg3);
}

void EpsNormalize(const FstClass &ifst, MutableFstClass *ofst,
                  EpsNormalizeType norm_type = EPS_NORM_INPUT);

}  // namespace script
}  // namespace fst

#endif  // FST_SCRIPT_EPSNORMALIZE_H_
