
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

#include <fst/script/text-io.h>

#include <cstring>
#include <sstream>
#include <utility>
using std::pair; using std::make_pair;

#include <fst/types.h>
#include <fst/util.h>

namespace fst {
namespace script {

// Reads vector of weights; returns true on success.
bool ReadPotentials(const string &weight_type,
                    const string& filename,
                    vector<WeightClass>* potential) {
  ifstream strm(filename.c_str());
  if (!strm.good()) {
    LOG(ERROR) << "ReadPotentials: Can't open file: " << filename;
    return false;
  }

  const int kLineLen = 8096;
  char line[kLineLen];
  size_t nline = 0;

  potential->clear();
  while (!strm.getline(line, kLineLen).fail()) {
    ++nline;
    vector<char *> col;
    SplitToVector(line, "\n\t ", &col, true);
    if (col.size() == 0 || col[0][0] == '\0')  // empty line
      continue;
    if (col.size() != 2) {
      LOG(ERROR) << "ReadPotentials: Bad number of columns, "
                 << "file = " << filename << ", line = " << nline;
      return false;
    }

    ssize_t s = StrToInt64(col[0], filename, nline, false);
    WeightClass weight(weight_type, col[1]);

    while (potential->size() <= s)
      potential->push_back(WeightClass::Zero());
    (*potential)[s] = weight;
  }
  return true;
}

// Writes vector of weights; returns true on success.
bool WritePotentials(const string& filename,
                     const vector<WeightClass>& potential) {
  ostream *strm = &cout;
  if (!filename.empty()) {
    strm = new ofstream(filename.c_str());
    if (!strm->good()) {
      LOG(ERROR) << "WritePotentials: Can't open file: " << filename;
      delete strm;
      return false;
    }
  }

  strm->precision(9);
  for (ssize_t s = 0; s < potential.size(); ++s)
    *strm << s << "\t" << potential[s] << "\n";

  if (strm->fail())
    LOG(ERROR) << "WritePotentials: Write failed: "
               << (filename.empty() ? "standard output" : filename);
  bool ret = !strm->fail();
  if (strm != &cout)
    delete strm;
  return ret;
}


}  // namespace script
}  // namespace fst
