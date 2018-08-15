
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

#ifndef FST_SCRIPT_INFO_H_
#define FST_SCRIPT_INFO_H_

#include <fst/script/arg-packs.h>
#include <fst/script/fst-class.h>
#include <fst/script/info-impl.h>

namespace fst {
namespace script {

typedef args::Package<const FstClass&, bool, const string&,
                      const string&, bool, bool> InfoArgs;

template<class Arc>
void PrintFstInfo(InfoArgs *args) {
  const Fst<Arc> &fst = *(args->arg1.GetFst<Arc>());
  FstInfo<Arc> fstinfo(fst, args->arg2, args->arg3,
                       args->arg4, args->arg5);
  PrintFstInfo(fstinfo, args->arg6);

  if (args->arg6)
    fst.Write("");
}

void PrintFstInfo(const FstClass &f, bool test_properties,
                  const string &arc_filter, const string &info_type,
                  bool pipe, bool verify);

}  // namespace script
}  // namespace fst

#endif  // FST_SCRIPT_INFO_H_
