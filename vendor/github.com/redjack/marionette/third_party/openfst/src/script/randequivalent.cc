
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
#include <fst/script/randequivalent.h>

namespace fst {
namespace script {

// 1
bool RandEquivalent(const FstClass &fst1, const FstClass &fst2,
                    int32 seed, ssize_t num_paths, float delta,
                    int path_length) {
  if (!ArcTypesMatch(fst1, fst2, "RandEquivalent")) return false;
  RandEquivalentInnerArgs1 args(fst1, fst2, seed, num_paths, delta,
                                path_length);
  RandEquivalentArgs1 args_with_retval(args);

  Apply<Operation<RandEquivalentArgs1> >("RandEquivalent", fst1.ArcType(),
                                         &args_with_retval);
  return args_with_retval.retval;
}

// 2
bool RandEquivalent(const FstClass &fst1, const FstClass &fst2, int32 seed,
                    ssize_t num_paths, float delta,
                    const RandGenOptions<RandArcSelection> &opts) {
  if (!ArcTypesMatch(fst1, fst2, "RandEquivalent")) return false;

  RandEquivalentInnerArgs2 args(fst1, fst2, seed, num_paths, delta, opts);
  RandEquivalentArgs2 args_with_retval(args);

  Apply<Operation<RandEquivalentArgs2> >(
      "RandEquivalent", fst1.ArcType(), &args_with_retval);

  return args_with_retval.retval;
}

REGISTER_FST_OPERATION(RandEquivalent, StdArc, RandEquivalentArgs1);
REGISTER_FST_OPERATION(RandEquivalent, LogArc, RandEquivalentArgs1);
REGISTER_FST_OPERATION(RandEquivalent, Log64Arc, RandEquivalentArgs1);
REGISTER_FST_OPERATION(RandEquivalent, StdArc, RandEquivalentArgs2);
REGISTER_FST_OPERATION(RandEquivalent, LogArc, RandEquivalentArgs2);
REGISTER_FST_OPERATION(RandEquivalent, Log64Arc, RandEquivalentArgs2);

}  // namespace script
}  // namespace fst
