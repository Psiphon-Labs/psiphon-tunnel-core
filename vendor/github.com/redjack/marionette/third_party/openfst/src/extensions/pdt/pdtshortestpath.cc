// pdtshortestpath.cc

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
// Modified: jpr@google.com (Jake Ratkiewicz) to use FstClass
//
// \file
// Return the shortest path in a (bounded-stack) PDT.
//

#include <fst/extensions/pdt/pdtscript.h>
#include <fst/util.h>


DEFINE_bool(keep_parentheses, false, "Keep PDT parentheses in result.");
DEFINE_string(queue_type, "fifo", "Queue type: one of: "
              "\"fifo\", \"lifo\", \"state\"");
DEFINE_bool(path_gc, true, "Garbage collect shortest path data");
DEFINE_string(pdt_parentheses, "", "PDT parenthesis label pairs.");

int main(int argc, char **argv) {
  namespace s = fst::script;

  string usage = "Shortest path in a (bounded-stack) PDT.\n\n  Usage: ";
  usage += argv[0];
  usage += " in.pdt [out.fst]\n";

  std::set_new_handler(FailedNewHandler);
  SET_FLAGS(usage.c_str(), &argc, &argv, true);
  if (argc > 3) {
    ShowUsage();
    return 1;
  }

  string in_name = (argc > 1 && (strcmp(argv[1], "-") != 0)) ? argv[1] : "";
  string out_name = argc > 2 ? argv[2] : "";

  s::FstClass *ifst = s::FstClass::Read(in_name);
  if (!ifst) return 1;

  if (FLAGS_pdt_parentheses.empty()) {
    LOG(ERROR) << argv[0] << ": No PDT parenthesis label pairs provided";
    return 1;
  }

  vector<pair<int64, int64> > parens, rparens;
  fst::ReadLabelPairs(FLAGS_pdt_parentheses, &parens, false);

  s::VectorFstClass ofst(ifst->ArcType());

  fst::QueueType qt;

  if (FLAGS_queue_type == "fifo") {
    qt = fst::FIFO_QUEUE;
  } else if (FLAGS_queue_type == "lifo") {
    qt = fst::LIFO_QUEUE;
  } else if (FLAGS_queue_type == "state") {
    qt = fst::STATE_ORDER_QUEUE;
  } else {
    LOG(ERROR) << "Unknown or unsupported queue type: " << FLAGS_queue_type;
    return 1;
  }

  s::PdtShortestPathOptions opts(qt, FLAGS_keep_parentheses, FLAGS_path_gc);
  s::PdtShortestPath(*ifst, parens, &ofst, opts);
  ofst.Write(out_name);

  return 0;
}
