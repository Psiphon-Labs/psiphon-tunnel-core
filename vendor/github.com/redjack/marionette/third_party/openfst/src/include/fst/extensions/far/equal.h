
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
// Author: allauzen@google.com (Cyril Allauzen)

#ifndef FST_EXTENSIONS_FAR_EQUAL_H_
#define FST_EXTENSIONS_FAR_EQUAL_H_

#include <string>

#include <fst/extensions/far/far.h>
#include <fst/equal.h>

namespace fst {

template <class Arc>
bool FarEqual(const string &filename1,
             const string &filename2,
             float delta = kDelta,
             const string &begin_key = string(),
             const string &end_key = string()) {

  FarReader<Arc> *reader1 = FarReader<Arc>::Open(filename1);
  FarReader<Arc> *reader2 = FarReader<Arc>::Open(filename2);
  if (!reader1 || !reader2) {
    delete reader1;
    delete reader2;
    VLOG(1) << "FarEqual: cannot open input Far file(s)";
    return false;
  }

  if (!begin_key.empty()) {
    bool find_begin1 = reader1->Find(begin_key);
    bool find_begin2 = reader2->Find(begin_key);
    if (!find_begin1 || !find_begin2) {
      bool ret = !find_begin1 && !find_begin2;
      if (!ret) {
        VLOG(1) << "FarEqual: key \"" << begin_key << "\" missing from "
                << (find_begin1 ? "second" : "first") << " archive.";
      }
      delete reader1;
      delete reader2;
      return ret;
    }
  }

  for(; !reader1->Done() && !reader2->Done();
      reader1->Next(), reader2->Next()) {
    const string key1 = reader1->GetKey();
    const string key2 = reader2->GetKey();
    if (!end_key.empty() && end_key < key1 && end_key < key2) {
      delete reader1;
      delete reader2;
      return true;
    }
    if (key1 != key2) {
      VLOG(1) << "FarEqual: mismatched keys \""
              << key1 << "\" <> \"" << key2 << "\".";
      delete reader1;
      delete reader2;
      return false;
    }
    if (!Equal(reader1->GetFst(), reader2->GetFst(), delta)) {
      VLOG(1) << "FarEqual: Fsts for key \"" << key1 << "\" are not equal.";
      delete reader1;
      delete reader2;
      return false;
    }
  }

  if (!reader1->Done() || !reader2->Done()) {
    VLOG(1) << "FarEqual: key \""
            << (reader1->Done() ? reader2->GetKey() : reader1->GetKey())
            << "\" missing form " << (reader2->Done() ? "first" : "second")
            << " archive.";
    delete reader1;
    delete reader2;
    return false;
  }

  delete reader1;
  delete reader2;
  return true;
}

}  // namespace fst

#endif  // FST_EXTENSIONS_FAR_EQUAL_H_
