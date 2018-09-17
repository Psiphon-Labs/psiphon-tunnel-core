
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
#include <fst/script/equivalent.h>

namespace fst {
namespace script {

bool Equivalent(const FstClass &fst1, const FstClass &fst2,
                float delta) {
  if (!ArcTypesMatch(fst1, fst2, "Equivalent")) return false;

  EquivalentInnerArgs args(fst1, fst2, delta);
  EquivalentArgs args_with_retval(args);

  Apply<Operation<EquivalentArgs> >("Equivalent", fst1.ArcType(),
                                    &args_with_retval);

  return args_with_retval.retval;
}

REGISTER_FST_OPERATION(Equivalent, StdArc, EquivalentArgs);
REGISTER_FST_OPERATION(Equivalent, LogArc, EquivalentArgs);
REGISTER_FST_OPERATION(Equivalent, Log64Arc, EquivalentArgs);

}  // namespace script
}  // namespace fst
