
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

#include <fst/extensions/far/compile-strings.h>
#include <iostream>
#include <fstream>
#include <sstream>

DEFINE_string(far_field_separator, "\t",
              "Set of characters used as a separator between printed fields");

namespace fst {

// Compute the minimal length required to
// encode each line number as a decimal number
int KeySize(const char *filename) {
  ifstream istrm(filename);
  istrm.seekg(0);
  string s;
  int nline = 0;
  while (getline(istrm, s))
    ++nline;
  istrm.seekg(0);
  return nline ? ceil(log10(nline + 1)) : 1;
}

}  // namespace fst
