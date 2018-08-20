// main.h

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
// \file
// Classes and functions for registering and invoking Far main
// functions that support multiple and extensible arc types.

#ifndef FST_EXTENSIONS_FAR_MAIN_H__
#define FST_EXTENSIONS_FAR_MAIN_H__

#include <fst/extensions/far/far.h>

namespace fst {

FarEntryType StringToFarEntryType(const string &s);
FarTokenType StringToFarTokenType(const string &s);

// Return the 'FarType' value corresponding to a far type name.
FarType FarTypeFromString(const string &str);

// Return the textual name  corresponding to a 'FarType;.
string FarTypeToString(FarType type);

string LoadArcTypeFromFar(const string& far_fname);
string LoadArcTypeFromFst(const string& far_fname);

}  // namespace fst

#endif  // FST_EXTENSIONS_FAR_MAIN_H__
