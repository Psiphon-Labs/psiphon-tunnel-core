
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
#include <fst/script/print.h>

namespace fst {
namespace script {

void PrintFst(const FstClass &fst, ostream &ostrm, const string &dest,
              const SymbolTable *isyms,
              const SymbolTable *osyms,
              const SymbolTable *ssyms,
              bool accept, bool show_weight_one) {
  string sep = FLAGS_fst_field_separator.substr(0, 1);
  FstPrinterArgs args(fst, isyms, osyms, ssyms, accept, show_weight_one,
                      &ostrm, dest, sep);
  Apply<Operation<FstPrinterArgs> >("PrintFst", fst.ArcType(), &args);
}

REGISTER_FST_OPERATION(PrintFst, StdArc, FstPrinterArgs);
REGISTER_FST_OPERATION(PrintFst, LogArc, FstPrinterArgs);
REGISTER_FST_OPERATION(PrintFst, Log64Arc, FstPrinterArgs);

}  // namespace script
}  // namespace fst
