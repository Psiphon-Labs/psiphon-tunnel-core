
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

#include <fst/script/script-impl.h>

namespace fst {
namespace script {

//
// Utility function for checking that arc types match.
//
bool ArcTypesMatch(const FstClass &a, const FstClass &b,
                   const string &op_name) {
  if (a.ArcType() != b.ArcType()) {
    LOG(ERROR) << "FSTs with non-matching arc types passed to " << op_name
               << ":\n\t" << a.ArcType() << " and " << b.ArcType();
    return false;
  } else {
    return true;
  }
}

}  // namespace script
}  // namespace fst
