
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
#include <fst/script/decode.h>
#include <fst/encode.h>

namespace fst {
namespace script {

void Decode(MutableFstClass *ofst, const string &coder_fname) {
  DecodeArgs args(ofst, coder_fname);

  Apply<Operation<DecodeArgs> >("Decode", ofst->ArcType(), &args);
}

REGISTER_FST_OPERATION(Decode, StdArc, DecodeArgs);
REGISTER_FST_OPERATION(Decode, LogArc, DecodeArgs);
REGISTER_FST_OPERATION(Decode, Log64Arc, DecodeArgs);

}  // namespace script
}  // namespace fst
