
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

#ifndef FST_SCRIPT_CONVERT_H_
#define FST_SCRIPT_CONVERT_H_

#include <string>

#include <fst/script/arg-packs.h>
#include <fst/script/fst-class.h>

namespace fst {
namespace script {

typedef args::Package<const FstClass&, const string&> ConvertInnerArgs;
typedef args::WithReturnValue<FstClass*, ConvertInnerArgs> ConvertArgs;

template<class Arc>
void Convert(ConvertArgs *args) {
  const Fst<Arc> &fst = *(args->args.arg1.GetFst<Arc>());
  const string &new_type = args->args.arg2;

  Fst<Arc> *result = Convert(fst, new_type);
  args->retval = new FstClass(*result);
  delete result;
}

#ifdef SWIG
%newobject Convert;
#endif
FstClass *Convert(const FstClass& f, const string &new_type);

}  // namespace script
}  // namespace fst

#endif  // FST_SCRIPT_CONVERT_H_
