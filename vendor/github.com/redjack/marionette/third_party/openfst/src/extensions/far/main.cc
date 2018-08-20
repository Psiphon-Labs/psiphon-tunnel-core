// main.cc

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
// Modified: jpr@google.com (Jake Ratkiewicz) to not use new arc-dispatch
//
// \file
// Definitions and functions for invoking and using Far main
// functions that support multiple and extensible arc types.

#include <string>
#include <vector>
using std::vector;

#include <iostream>
#include <fstream>
#include <sstream>
#include <fst/extensions/far/main.h>

namespace fst {

// Return the 'FarType' value corresponding to a far type name.
FarType FarTypeFromString(const string &str) {
  FarType type = FAR_DEFAULT;
  if (str == "fst")
    type = FAR_FST;
  else if (str == "stlist")
    type = FAR_STLIST;
  else if (str == "sttable")
    type = FAR_STTABLE;
  else if (str == "default")
    type = FAR_DEFAULT;
  return type;
}


// Return the textual name  corresponding to a 'FarType;.
string FarTypeToString(FarType type) {
  switch (type) {
    case FAR_FST:
      return "fst";
    case FAR_STLIST:
      return "stlist";
    case FAR_STTABLE:
      return "sttable";
    case FAR_DEFAULT:
      return "default";
    default:
      return "<unknown>";
  }
}

FarEntryType StringToFarEntryType(const string &s) {
  if (s == "line") {
    return FET_LINE;
  } else if (s == "file") {
    return FET_FILE;
  } else {
    FSTERROR() << "Unknown FAR entry type: " << s;
    return FET_LINE;  // compiler requires return
  }
}

FarTokenType StringToFarTokenType(const string &s) {
  if (s == "symbol") {
    return FTT_SYMBOL;
  } else if (s == "byte") {
    return FTT_BYTE;
  } else if (s == "utf8") {
    return FTT_UTF8;
  } else {
    FSTERROR() << "Unknown FAR entry type: " << s;
    return FTT_SYMBOL;  // compiler requires return
  }
}


string LoadArcTypeFromFar(const string &far_fname) {
  FarHeader hdr;

  if (!hdr.Read(far_fname)) {
    FSTERROR() << "Error reading FAR: " << far_fname;
    return "";
  }

  string atype = hdr.ArcType();
  if (atype == "unknown") {
    FSTERROR() << "Empty FST archive: " << far_fname;
    return "";
  }

  return atype;
}

string LoadArcTypeFromFst(const string &fst_fname) {
  FstHeader hdr;
  ifstream in(fst_fname.c_str(), ifstream::in | ifstream::binary);
  if (!hdr.Read(in, fst_fname)) {
    FSTERROR() << "Error reading FST: " << fst_fname;
    return "";
  }

  return hdr.ArcType();
}

}  // namespace fst
