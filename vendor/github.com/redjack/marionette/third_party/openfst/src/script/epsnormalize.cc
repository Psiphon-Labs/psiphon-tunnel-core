
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

#include <fst/script/fst-class.h>
#include <fst/script/script-impl.h>
#include <fst/script/epsnormalize.h>

namespace fst {
namespace script {

void EpsNormalize(const FstClass &ifst, MutableFstClass *ofst,
                  EpsNormalizeType norm_type) {
  if (!ArcTypesMatch(ifst, *ofst, "EpsNormalize")) return;

  EpsNormalizeArgs args(ifst, ofst, norm_type);
  Apply<Operation<EpsNormalizeArgs> >("EpsNormalize", ifst.ArcType(), &args);
}

REGISTER_FST_OPERATION(EpsNormalize, StdArc, EpsNormalizeArgs);
REGISTER_FST_OPERATION(EpsNormalize, LogArc, EpsNormalizeArgs);
REGISTER_FST_OPERATION(EpsNormalize, Log64Arc, EpsNormalizeArgs);

}  // namespace script
}  // namespace fst
