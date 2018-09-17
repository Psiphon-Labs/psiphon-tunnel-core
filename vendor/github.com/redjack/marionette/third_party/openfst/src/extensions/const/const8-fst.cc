
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
#include <fst/const-fst.h>

using fst::FstRegisterer;
using fst::ConstFst;
using fst::LogArc;
using fst::Log64Arc;
using fst::StdArc;

// Register ConstFst for common arcs types with uint8 size type
static FstRegisterer< ConstFst<StdArc, uint8> >
        ConstFst_StdArc_uint8_registerer;
static FstRegisterer< ConstFst<LogArc, uint8> >
        ConstFst_LogArc_uint8_registerer;
static FstRegisterer< ConstFst<Log64Arc, uint8> >
        ConstFst_Log64Arc_uint8_registerer;
