
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
// Author: jpr@google.com (Jake Ratkiewicz)

#include <string>

#include <fst/arc.h>
#include <fst/script/weight-class.h>

namespace fst {
namespace script {

REGISTER_FST_WEIGHT(StdArc::Weight);
REGISTER_FST_WEIGHT(LogArc::Weight);
REGISTER_FST_WEIGHT(Log64Arc::Weight);

WeightClass::WeightClass(const string &weight_type,
                         const string &weight_str)
  : element_type_(OTHER) {
  WeightClassRegister *reg = WeightClassRegister::GetRegister();

  StrToWeightImplBaseT stw = reg->GetEntry(weight_type);

  impl_ = stw(weight_str, "WeightClass", 0);
}

ostream& operator << (ostream &o, const WeightClass &c) {
  c.impl_->Print(&o);
  return o;
}

}  // namespace script
}  // namespace fst
