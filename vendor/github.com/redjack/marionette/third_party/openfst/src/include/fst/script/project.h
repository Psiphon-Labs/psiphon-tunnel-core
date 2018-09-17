
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

#ifndef FST_SCRIPT_PROJECT_H_
#define FST_SCRIPT_PROJECT_H_

#include <fst/script/arg-packs.h>
#include <fst/script/fst-class.h>
#include <fst/project.h>  // for ProjectType

namespace fst {
namespace script {

typedef args::Package<MutableFstClass*, ProjectType> ProjectArgs;

template<class Arc>
void Project(ProjectArgs *args) {
  MutableFst<Arc> *ofst = args->arg1->GetMutableFst<Arc>();

  Project(ofst, args->arg2);
}

void Project(MutableFstClass *ofst, ProjectType project_type);

}  // namespace script
}  // namespace fst



#endif  // FST_SCRIPT_PROJECT_H_
