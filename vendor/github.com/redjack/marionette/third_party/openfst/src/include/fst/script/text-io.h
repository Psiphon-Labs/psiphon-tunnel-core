// text-io.h

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
// Modified: jpr@google.com (Jake Ratkiewicz) to work with generic WeightClass
//
// \file
// Utilities for reading and writing textual strings representing
// states, labels, and weights and files specifying label-label pairs
// and potentials (state-weight pairs).
//

#ifndef FST_SCRIPT_TEXT_IO_H__
#define FST_SCRIPT_TEXT_IO_H__

#include <string>
#include <vector>
using std::vector;


#include <iostream>
#include <fstream>
#include <sstream>
#include <fst/script/weight-class.h>

namespace fst {
namespace script {

bool ReadPotentials(const string &weight_type,
                    const string& filename,
                    vector<WeightClass>* potential);

bool WritePotentials(const string& filename,
                     const vector<WeightClass>& potential);

}  // namespace script
}  // namespace fst

#endif  // FST_SCRIPT_TEXT_IO_H__
