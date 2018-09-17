
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

#include <string>

#include <fst/script/fst-class.h>
#include <fst/script/script-impl.h>
#include <fst/script/info.h>

namespace fst {
namespace script {

void PrintFstInfo(const FstClass &f, bool test_properties,
                  const string &arc_filter, const string &info_type,
                  bool pipe, bool verify) {
  InfoArgs args(f, test_properties, arc_filter, info_type, pipe, verify);

  Apply<Operation<InfoArgs> >("PrintFstInfo", f.ArcType(), &args);
}

REGISTER_FST_OPERATION(PrintFstInfo, StdArc, InfoArgs);
REGISTER_FST_OPERATION(PrintFstInfo, LogArc, InfoArgs);
REGISTER_FST_OPERATION(PrintFstInfo, Log64Arc, InfoArgs);

}  // namespace script
}  // namespace fst
