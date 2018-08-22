// extract-main.h

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
// Author: riley@google.com (Michael Riley)
// Modified: jpr@google.com (Jake Ratkiewicz) to use the new arc-dispatch

// \file
// Extracts component FSTs from an finite-state archive.
//

#ifndef FST_EXTENSIONS_FAR_EXTRACT_H__
#define FST_EXTENSIONS_FAR_EXTRACT_H__

#include <string>
#include <vector>
using std::vector;

#include <fst/extensions/far/far.h>

namespace fst {

template<class Arc>
inline void FarWriteFst(const Fst<Arc>* fst, string key,
                        string* okey, int* nrep,
                        const int32 &generate_filenames, int i,
                        const string &filename_prefix,
                        const string &filename_suffix) {
  if (key == *okey)
    ++*nrep;
  else
    *nrep = 0;

  *okey = key;

  string ofilename;
  if (generate_filenames) {
    ostringstream tmp;
    tmp.width(generate_filenames);
    tmp.fill('0');
    tmp << i;
    ofilename = tmp.str();
  } else {
    if (*nrep > 0) {
      ostringstream tmp;
      tmp << '.' << nrep;
      key.append(tmp.str().data(), tmp.str().size());
    }
    ofilename = key;
  }
  fst->Write(filename_prefix + ofilename + filename_suffix);
}

template<class Arc>
void FarExtract(const vector<string> &ifilenames,
                const int32 &generate_filenames,
                const string &keys,
                const string &key_separator,
                const string &range_delimiter,
                const string &filename_prefix,
                const string &filename_suffix) {
  FarReader<Arc> *far_reader = FarReader<Arc>::Open(ifilenames);
  if (!far_reader) return;

  string okey;
  int nrep = 0;

  vector<char *> key_vector;
  // User has specified a set of fsts to extract, where some of the "fsts" could
  // be ranges.
  if (!keys.empty()) {
    char *keys_cstr = new char[keys.size()+1];
    strcpy(keys_cstr, keys.c_str());
    SplitToVector(keys_cstr, key_separator.c_str(), &key_vector, true);
    int i = 0;
    for (int k = 0; k < key_vector.size(); ++k, ++i) {
      string key = string(key_vector[k]);
      char *key_cstr = new char[key.size()+1];
      strcpy(key_cstr, key.c_str());
      vector<char *> range_vector;
      SplitToVector(key_cstr, range_delimiter.c_str(), &range_vector, false);
      if (range_vector.size() == 1) {  // Not a range
        if (!far_reader->Find(key)) {
          LOG(ERROR) << "FarExtract: Cannot find key: " << key;
          return;
        }
        const Fst<Arc> &fst = far_reader->GetFst();
        FarWriteFst(&fst, key, &okey, &nrep, generate_filenames, i,
                    filename_prefix, filename_suffix);
      } else if (range_vector.size() == 2) {  // A legal range
        string begin_key = string(range_vector[0]);
        string end_key = string(range_vector[1]);
        if (begin_key.empty() || end_key.empty()) {
          LOG(ERROR) << "FarExtract: Illegal range specification: " << key;
          return;
        }
        if (!far_reader->Find(begin_key)) {
          LOG(ERROR) << "FarExtract: Cannot find key: " << begin_key;
          return;
        }
        for ( ; !far_reader->Done(); far_reader->Next(), ++i) {
          string ikey = far_reader->GetKey();
          if (end_key < ikey) break;
          const Fst<Arc> &fst = far_reader->GetFst();
          FarWriteFst(&fst, ikey, &okey, &nrep, generate_filenames, i,
                      filename_prefix, filename_suffix);
        }
      } else {
        LOG(ERROR) << "FarExtract: Illegal range specification: " << key;
        return;
      }
      delete [] key_cstr;
    }
    delete [] keys_cstr;
    return;
  }
  // Nothing specified: extract everything.
  for (int i = 1; !far_reader->Done(); far_reader->Next(), ++i) {
    string key = far_reader->GetKey();
    const Fst<Arc> &fst = far_reader->GetFst();
    FarWriteFst(&fst, key, &okey, &nrep, generate_filenames, i,
                filename_prefix, filename_suffix);
  }
  return;
}

}  // namespace fst

#endif  // FST_EXTENSIONS_FAR_EXTRACT_H__
