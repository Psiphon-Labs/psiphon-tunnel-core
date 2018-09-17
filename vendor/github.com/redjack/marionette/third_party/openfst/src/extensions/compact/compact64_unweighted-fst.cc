
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

#include <fst/fst.h>
#include <fst/compact-fst.h>

using fst::FstRegisterer;
using fst::CompactFst;
using fst::LogArc;
using fst::StdArc;
using fst::UnweightedCompactor;

static FstRegisterer<
  CompactFst<StdArc, UnweightedCompactor<StdArc>, uint64> >
CompactFst_StdArc_UnweightedCompactor_uint64_registerer;
static FstRegisterer<
  CompactFst<LogArc, UnweightedCompactor<LogArc>, uint64> >
CompactFst_LogArc_UnweightedCompactor_uint64_registerer;
