
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
// Modified: jpr@google.com (Jake Ratkiewicz)

#ifndef FST_EXTENSIONS_FAR_INFO_H_
#define FST_EXTENSIONS_FAR_INFO_H_

#include <iomanip>
#include <set>
#include <string>
#include <vector>
using std::vector;

#include <fst/extensions/far/far.h>
#include <fst/extensions/far/main.h>  // For FarTypeToString

namespace fst {

template <class Arc>
void CountStatesAndArcs(const Fst<Arc> &fst,
                        size_t *nstate,
                        size_t *narc,
                        size_t *nfinal) {
  StateIterator<Fst<Arc> > siter(fst);
  for (; !siter.Done(); siter.Next(), ++(*nstate)) {
    ArcIterator<Fst<Arc> > aiter(fst, siter.Value());
    for (; !aiter.Done(); aiter.Next(), ++(*narc)) {}
    if (fst.Final(siter.Value()) != Arc::Weight::Zero())
      ++(*nfinal);
  }
}

struct KeyInfo {
  string key;
  string type;
  size_t nstate;
  size_t narc;
  size_t nfinal;

  KeyInfo(string k, string t, int64 ns = 0, int64 na = 0, int nf = 0)
      : key(k), type(t), nstate(ns), narc(na), nfinal(nf) {}
};

template <class Arc>
void FarInfo(const vector<string> &filenames, const string &begin_key,
             const string &end_key, const bool list_fsts) {
  FarReader<Arc> *far_reader = FarReader<Arc>::Open(filenames);
  if (!far_reader) return;

  if (!begin_key.empty())
    far_reader->Find(begin_key);

  vector<KeyInfo> *infos = list_fsts ? new vector<KeyInfo>() : 0;
  size_t nfst = 0, nstate = 0, narc = 0, nfinal = 0;
  set<string> fst_types;
  for (; !far_reader->Done(); far_reader->Next()) {
    string key = far_reader->GetKey();
    if (!end_key.empty() && end_key < key)
      break;
    ++nfst;
    const Fst<Arc> &fst = far_reader->GetFst();
    fst_types.insert(fst.Type());
    if (infos) {
      KeyInfo info(key, fst.Type());
      CountStatesAndArcs(fst, &info.nstate, &info.narc, &info.nfinal);
      nstate += info.nstate;
      narc += info.narc;
      nfinal += info.nfinal;
      infos->push_back(info);
    } else {
      CountStatesAndArcs(fst, &nstate, &narc, &nfinal);
    }
  }

  if (!infos) {
    cout << std::left << setw(50) << "far type"
         << FarTypeToString(far_reader->Type()) << endl;
    cout << std::left << setw(50) << "arc type" << Arc::Type() << endl;
    cout << std::left << setw(50) << "fst type";
    for (set<string>::const_iterator iter = fst_types.begin();
         iter != fst_types.end();
         ++iter) {
      if (iter != fst_types.begin())
        cout << ",";
      cout << *iter;
    }
    cout << endl;
    cout << std::left << setw(50) << "# of FSTs" << nfst << endl;
    cout << std::left << setw(50) << "total # of states" << nstate << endl;
    cout << std::left << setw(50) << "total # of arcs" << narc << endl;
    cout << std::left << setw(50) << "total # of final states" << nfinal
         << endl;

  } else  {
    int wkey = 10, wtype = 10, wnstate = 14, wnarc = 12, wnfinal = 20;
    for (size_t i = 0; i < infos->size(); ++i) {
      const KeyInfo &info = (*infos)[i];
      if (info.key.size() + 2 > wkey)
        wkey = info.key.size() + 2;
      if (info.type.size() + 2 > wtype)
        wtype = info.type.size() + 2;
      if (ceil(log10(info.nstate)) + 2 > wnstate)
        wnstate = ceil(log10(info.nstate)) + 2;
      if (ceil(log10(info.narc)) + 2 > wnarc)
        wnarc = ceil(log10(info.narc)) + 2;
      if (ceil(log10(info.nfinal)) + 2 > wnfinal)
        wnfinal = ceil(log10(info.nfinal)) + 2;
    }

    cout << std::left << setw(wkey) << "key" << setw(wtype) << "type"
         << std::right << setw(wnstate) << "# of states" << setw(wnarc)
         << "# of arcs" << setw(wnfinal) << "# of final states" << endl;

    for (size_t i = 0; i < infos->size(); ++i) {
      const KeyInfo &info = (*infos)[i];
      cout << std::left << setw(wkey) << info.key << setw(wtype) << info.type
           << std::right << setw(wnstate) << info.nstate
           << setw(wnarc) << info.narc  << setw(wnfinal) << info.nfinal << endl;
    }
  }
}

}  // namespace fst


#endif  // FST_EXTENSIONS_FAR_INFO_H_
