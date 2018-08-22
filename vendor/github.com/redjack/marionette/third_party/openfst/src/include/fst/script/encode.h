
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

#ifndef FST_SCRIPT_ENCODE_H_
#define FST_SCRIPT_ENCODE_H_

#include <string>

#include <fst/script/arg-packs.h>
#include <fst/script/fst-class.h>
#include <fst/encode.h>

namespace fst {
namespace script {

typedef args::Package<MutableFstClass*, uint32, bool,
                      const string &> EncodeArgs;

template<class Arc>
void Encode(EncodeArgs *args) {
  MutableFst<Arc> *ofst = args->arg1->GetMutableFst<Arc>();
  bool reuse_encoder = args->arg3;
  const string &coder_fname = args->arg4;
  uint32 flags = args->arg2;

  EncodeMapper<Arc> *encoder = reuse_encoder
      ? EncodeMapper<Arc>::Read(coder_fname, ENCODE)
      : new EncodeMapper<Arc>(flags, ENCODE);

  Encode(ofst, encoder);
  if (!args->arg3)
    encoder->Write(coder_fname);

  delete encoder;
}

void Encode(MutableFstClass *fst, uint32 flags, bool reuse_encoder,
            const string &coder_fname);

}  // namespace script
}  // namespace fst



#endif  // FST_SCRIPT_ENCODE_H_
