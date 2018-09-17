
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
#include <fst/encode.h>
#include <fst/script/encode.h>

namespace fst {
namespace script {

void Encode(MutableFstClass *ofst, uint32 flags, bool reuse_encoder,
            const string &coder_fname) {
  EncodeArgs args(ofst, flags, reuse_encoder, coder_fname);

  Apply<Operation<EncodeArgs> >("Encode", ofst->ArcType(), &args);
}

REGISTER_FST_OPERATION(Encode, StdArc, EncodeArgs);
REGISTER_FST_OPERATION(Encode, LogArc, EncodeArgs);
REGISTER_FST_OPERATION(Encode, Log64Arc, EncodeArgs);

}  // namespace script
}  // namespace fst
