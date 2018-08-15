
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
#include <fst/script/shortest-distance.h>

namespace fst {
namespace script {

// 1
void ShortestDistance(const FstClass &fst, vector<WeightClass> *distance,
                      const ShortestDistanceOptions &opts) {
  ShortestDistanceArgs1 args(fst, distance, opts);

  Apply<Operation<ShortestDistanceArgs1> >("ShortestDistance", fst.ArcType(),
                                           &args);
}

// 2
void ShortestDistance(const FstClass &ifst, vector<WeightClass> *distance,
                      bool reverse, double delta) {
  ShortestDistanceArgs2 args(ifst, distance, reverse, delta);

  Apply<Operation<ShortestDistanceArgs2> >("ShortestDistance", ifst.ArcType(),
      &args);
}

// 3
WeightClass ShortestDistance(const FstClass &ifst) {
  ShortestDistanceArgs3 args(ifst);

  Apply<Operation<ShortestDistanceArgs3> >("ShortestDistance", ifst.ArcType(),
      &args);

  return args.retval;
}

REGISTER_FST_OPERATION(ShortestDistance, StdArc, ShortestDistanceArgs1);
REGISTER_FST_OPERATION(ShortestDistance, LogArc, ShortestDistanceArgs1);
REGISTER_FST_OPERATION(ShortestDistance, Log64Arc, ShortestDistanceArgs1);

REGISTER_FST_OPERATION(ShortestDistance, StdArc, ShortestDistanceArgs2);
REGISTER_FST_OPERATION(ShortestDistance, LogArc, ShortestDistanceArgs2);
REGISTER_FST_OPERATION(ShortestDistance, Log64Arc, ShortestDistanceArgs2);

REGISTER_FST_OPERATION(ShortestDistance, StdArc, ShortestDistanceArgs3);
REGISTER_FST_OPERATION(ShortestDistance, LogArc, ShortestDistanceArgs3);
REGISTER_FST_OPERATION(ShortestDistance, Log64Arc, ShortestDistanceArgs3);


}  // namespace script
}  // namespace fst
