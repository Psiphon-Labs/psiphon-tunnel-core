
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
#include <fst/script/shortest-path.h>

namespace fst {
namespace script {

void ShortestPath(const FstClass &ifst, MutableFstClass *ofst,
                  vector<WeightClass> *distance,
                  const ShortestPathOptions &opts) {
  if (!ArcTypesMatch(ifst, *ofst, "ShortestPath")) return;

  ShortestPathArgs1 args(ifst, ofst, distance, opts);
  Apply<Operation<ShortestPathArgs1> >("ShortestPath", ifst.ArcType(), &args);
}

void ShortestPath(const FstClass &ifst, MutableFstClass *ofst,
                  size_t n, bool unique, bool first_path,
                  WeightClass weight_threshold, int64 state_threshold) {
  if (!ArcTypesMatch(ifst, *ofst, "ShortestPath")) return;

  ShortestPathArgs2 args(ifst, ofst, n, unique, first_path, weight_threshold,
                         state_threshold);
  Apply<Operation<ShortestPathArgs2> >("ShortestPath", ifst.ArcType(), &args);
}


REGISTER_FST_OPERATION(ShortestPath, StdArc, ShortestPathArgs1);
REGISTER_FST_OPERATION(ShortestPath, LogArc, ShortestPathArgs1);
REGISTER_FST_OPERATION(ShortestPath, Log64Arc, ShortestPathArgs1);

REGISTER_FST_OPERATION(ShortestPath, StdArc, ShortestPathArgs2);
REGISTER_FST_OPERATION(ShortestPath, LogArc, ShortestPathArgs2);
REGISTER_FST_OPERATION(ShortestPath, Log64Arc, ShortestPathArgs2);

}  // namespace script
}  // namespace fst
