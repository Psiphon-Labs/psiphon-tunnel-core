// create-main.h

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
// Modified: jpr@google.com (Jake Ratkiewicz) to use new dispatch
//
// \file
// Creates a finite-state archive from component FSTs.  Includes
// helper function for farcreate.cc that templates the main on the arc
// type to support multiple and extensible arc types.
//

#ifndef FST_EXTENSIONS_FAR_CREATE_H__
#define FST_EXTENSIONS_FAR_CREATE_H__

#include <libgen.h>
#include <string>
#include <vector>
using std::vector;

#include <fst/extensions/far/far.h>

namespace fst {

template <class Arc>
void FarCreate(const vector<string> &in_fnames,
               const string &out_fname,
               const int32 generate_keys,
               const bool file_list_input,
               const FarType &far_type,
               const string &key_prefix,
               const string &key_suffix) {
  FarWriter<Arc> *far_writer =
      FarWriter<Arc>::Create(out_fname, far_type);
  if (!far_writer) return;

  vector<string> inputs;
  if (file_list_input) {
    for (int i = 1; i < in_fnames.size(); ++i) {
      ifstream istrm(in_fnames[i].c_str());
      string str;
      while (getline(istrm, str))
        inputs.push_back(str);
    }
  } else {
    inputs = in_fnames;
  }

  for (int i = 0; i < inputs.size(); ++i) {
    Fst<Arc> *ifst = Fst<Arc>::Read(inputs[i]);
    if (!ifst) return;
    string key;
    if (generate_keys > 0) {
      ostringstream keybuf;
      keybuf.width(generate_keys);
      keybuf.fill('0');
      keybuf << i + 1;
      key = keybuf.str();
    } else {
      char* filename = new char[inputs[i].size() + 1];
      strcpy(filename, inputs[i].c_str());
      key = basename(filename);
      delete[] filename;
    }

    far_writer->Add(key_prefix + key + key_suffix, *ifst);
    delete ifst;
  }

  delete far_writer;
}

}  // namespace fst

#endif  // FST_EXTENSIONS_FAR_CREATE_H__
