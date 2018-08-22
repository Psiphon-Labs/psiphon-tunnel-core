
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

#ifndef FST_SCRIPT_PUSH_H_
#define FST_SCRIPT_PUSH_H_

#include <fst/script/arg-packs.h>
#include <fst/script/fst-class.h>
#include <fst/push.h>

namespace fst {
namespace script {

// 1
typedef args::Package<MutableFstClass*, ReweightType, float, bool> PushArgs1;

template<class Arc>
void Push(PushArgs1 *args) {
  MutableFst<Arc> *ofst = args->arg1->GetMutableFst<Arc>();

  if (args->arg2 == REWEIGHT_TO_FINAL) {
    fst::Push(ofst, REWEIGHT_TO_FINAL, args->arg3, args->arg4);
  } else {
    fst::Push(ofst, REWEIGHT_TO_INITIAL, args->arg3, args->arg4);
  }
}

// 2
typedef args::Package<const FstClass &, MutableFstClass *, uint32,
                      ReweightType, float> PushArgs2;

template<class Arc>
void Push(PushArgs2 *args) {
  const Fst<Arc> &ifst = *(args->arg1.GetFst<Arc>());
  MutableFst<Arc> *ofst = args->arg2->GetMutableFst<Arc>();

  if (args->arg4 == REWEIGHT_TO_FINAL) {
    fst::Push<Arc, REWEIGHT_TO_FINAL>(ifst, ofst, args->arg3, args->arg5);
  } else {
    fst::Push<Arc, REWEIGHT_TO_INITIAL>(ifst, ofst, args->arg3, args->arg5);
  }
}

// 1
void Push(MutableFstClass *ofst, ReweightType type, float delta = kDelta,
          bool remove_total_weight = false);

// 2
void Push(const FstClass &ifst, MutableFstClass *ofst, uint32 flags,
          ReweightType dir, float delta);

}  // namespace script
}  // namespace fst



#endif  // FST_SCRIPT_PUSH_H_
