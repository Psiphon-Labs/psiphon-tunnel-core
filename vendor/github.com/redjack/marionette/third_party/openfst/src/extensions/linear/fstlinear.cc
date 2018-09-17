
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
// Author: wuke

#include <fst/extensions/linear/linearscript.h>

DEFINE_string(arc_type, "standard", "Output arc type");

DEFINE_string(epsilon_symbol, "<eps>", "Epsilon symbol");
DEFINE_string(unknown_symbol, "<unk>", "Unknown word symbol");

DEFINE_string(vocab, "", "Path to the vocabulary file");
DEFINE_string(out, "", "Path to the output binary");

DEFINE_string(save_isymbols, "", "Save input symbol table to file");
DEFINE_string(save_fsymbols, "", "Save feature symbol table to file");
DEFINE_string(save_osymbols, "", "Save output symbol table to file");

int main(int argc, char **argv) {
  // TODO(wuke): more detailed usage
  std::set_new_handler(FailedNewHandler);
  SET_FLAGS(argv[0], &argc, &argv, true);
  fst::script::ValidateDelimiter();
  fst::script::ValidateEmptySymbol();

  if (argc == 1) {
    ShowUsage();
    return 1;
  }

  fst::script::LinearCompile(FLAGS_arc_type, FLAGS_epsilon_symbol,
                                 FLAGS_unknown_symbol, FLAGS_vocab, argv + 1,
                                 argc - 1, FLAGS_out, FLAGS_save_isymbols,
                                 FLAGS_save_fsymbols, FLAGS_save_osymbols);
}
