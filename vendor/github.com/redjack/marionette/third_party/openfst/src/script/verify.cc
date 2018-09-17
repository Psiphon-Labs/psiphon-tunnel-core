
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
#include <fst/script/verify.h>

namespace fst {
namespace script {

bool Verify(const FstClass &fst) {
  VerifyArgs args(&fst);

  Apply<Operation<VerifyArgs> >("Verify", fst.ArcType(), &args);

  return args.retval;
}

REGISTER_FST_OPERATION(Verify, StdArc, VerifyArgs);
REGISTER_FST_OPERATION(Verify, LogArc, VerifyArgs);
REGISTER_FST_OPERATION(Verify, Log64Arc, VerifyArgs);

}  // namespace script
}  // namespace fst
