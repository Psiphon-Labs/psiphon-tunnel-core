
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
#include <fst/script/compile.h>

namespace fst {
namespace script {

void CompileFst(istream &istrm, const string &source, const string &dest,
                const string &fst_type, const string &arc_type,
                const SymbolTable *isyms,
                const SymbolTable *osyms, const SymbolTable *ssyms,
                bool accep, bool ikeep, bool okeep, bool nkeep,
                bool allow_negative_labels) {
  FstCompileArgs args(istrm, source, dest, fst_type, isyms, osyms, ssyms,
                      accep, ikeep, okeep, nkeep, allow_negative_labels);

  Apply<Operation<FstCompileArgs> >("CompileFst", arc_type, &args);
}

REGISTER_FST_OPERATION(CompileFst, StdArc, FstCompileArgs);
REGISTER_FST_OPERATION(CompileFst, LogArc, FstCompileArgs);
REGISTER_FST_OPERATION(CompileFst, Log64Arc, FstCompileArgs);

}  // namespace script
}  // namespace fst
