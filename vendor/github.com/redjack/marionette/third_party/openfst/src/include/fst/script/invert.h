
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

#ifndef FST_SCRIPT_INVERT_H_
#define FST_SCRIPT_INVERT_H_

#include <fst/script/arg-packs.h>
#include <fst/script/fst-class.h>
#include <fst/invert.h>

namespace fst {
namespace script {

// The following confuses swig, because it has the same arguments
// as the non-templated version
#ifndef SWIG
template<class Arc>
void Invert(MutableFstClass *fst) {
  MutableFst<Arc> *typed_fst = fst->GetMutableFst<Arc>();

  Invert(typed_fst);
}
#endif

void Invert(MutableFstClass *fst);

}  // namespace script
}  // namespace fst

#endif  // FST_SCRIPT_INVERT_H_
