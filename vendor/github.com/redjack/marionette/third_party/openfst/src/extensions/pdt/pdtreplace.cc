// pdtreplace.cc

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
//
// Converts an RTN represented by FSTs and non-terminal labels into a PDT .

#include <utility>
using std::pair; using std::make_pair;
#include <vector>
using std::vector;
#include <fst/extensions/pdt/pdtscript.h>
#include <fst/vector-fst.h>
#include <fst/util.h>

DEFINE_string(pdt_parentheses, "", "PDT parenthesis label pairs.");

int main(int argc, char **argv) {
  namespace s = fst::script;

  string usage = "Converts an RTN represented by FSTs";
  usage += " and non-terminal labels into PDT";
  usage += " Usage: ";
  usage += argv[0];
  usage += " root.fst rootlabel [rule1.fst label1 ...] [out.fst]\n";

  std::set_new_handler(FailedNewHandler);
  SET_FLAGS(usage.c_str(), &argc, &argv, true);
  if (argc < 4) {
    ShowUsage();
    return 1;
  }

  string in_fname = argv[1];
  string out_fname = argc % 2 == 0 ? argv[argc - 1] : "";

  s::FstClass *ifst = s::FstClass::Read(in_fname);
  if (!ifst) return 1;

  typedef int64 Label;
  typedef pair<Label, const s::FstClass* > FstTuple;
  vector<FstTuple> fst_tuples;
  Label root = atoll(argv[2]);
  fst_tuples.push_back(make_pair(root, ifst));

  for (size_t i = 3; i < argc - 1; i += 2) {
    ifst = s::FstClass::Read(argv[i]);
    if (!ifst) return 1;
    Label lab = atoll(argv[i + 1]);
    fst_tuples.push_back(make_pair(lab, ifst));
  }

  s::VectorFstClass ofst(ifst->ArcType());
  vector<pair<int64, int64> > parens;
  s::PdtReplace(fst_tuples, &ofst, &parens, root);

  if (!FLAGS_pdt_parentheses.empty())
    fst::WriteLabelPairs(FLAGS_pdt_parentheses, parens);

  ofst.Write(out_fname);

  return 0;
}
