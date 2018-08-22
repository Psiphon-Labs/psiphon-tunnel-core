
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

// These classes are only recommended for use in high-level scripting
// applications. Most users should use the lower-level templated versions
// corresponding to these classes.

#include <fst/script/fst-class.h>
#include <fst/script/register.h>
#include <fst/fst-decl.h>
#include <fst/union.h>
#include <fst/reverse.h>
#include <fst/equal.h>

namespace fst {
namespace script {

//
//  REGISTRATION
//

REGISTER_FST_CLASSES(StdArc);
REGISTER_FST_CLASSES(LogArc);
REGISTER_FST_CLASSES(Log64Arc);

//
//  FST CLASS METHODS
//

template<class FstT>
FstT *ReadFst(istream &in, const string &fname) {
  if (!in) {
    LOG(ERROR) << "ReadFst: Can't open file: " << fname;
    return 0;
  }

  FstHeader hdr;
  if (!hdr.Read(in, fname)) {
    return 0;
  }

  FstReadOptions read_options(fname, &hdr);

  typename IORegistration<FstT>::Register *reg =
      IORegistration<FstT>::Register::GetRegister();

  const typename IORegistration<FstT>::Reader reader =
      reg->GetReader(hdr.ArcType());

  if (!reader) {
    LOG(ERROR) << "ReadFst : unknown arc type \""
               << hdr.ArcType() << "\" : " << read_options.source;
    return 0;
  }

  return reader(in, read_options);
}

FstClass *FstClass::Read(const string &fname) {
  if (!fname.empty()) {
    ifstream in(fname.c_str(), ifstream::in | ifstream::binary);
    return ReadFst<FstClass>(in, fname);
  } else {
    return ReadFst<FstClass>(cin, "standard input");
  }
}

FstClass *FstClass::Read(istream &istr, const string &source) {
  return ReadFst<FstClass>(istr, source);
}

//
//  MUTABLE FST CLASS METHODS
//

MutableFstClass *MutableFstClass::Read(const string &fname, bool convert) {
  if (convert == false) {
    if (!fname.empty()) {
      ifstream in(fname.c_str(), ifstream::in | ifstream::binary);
      return ReadFst<MutableFstClass>(in, fname);
    } else {
      return ReadFst<MutableFstClass>(cin, "standard input");
    }
  } else {  // Converts to VectorFstClass if not mutable.
    FstClass *ifst = FstClass::Read(fname);
    if (!ifst) return 0;
    if (ifst->Properties(fst::kMutable, false)) {
      return static_cast<MutableFstClass *>(ifst);
    } else {
      MutableFstClass *ofst = new VectorFstClass(*ifst);
      delete ifst;
      return ofst;
    }
  }
}

//
// VECTOR FST CLASS METHODS
//

IORegistration<VectorFstClass>::Entry GetVFSTRegisterEntry(
    const string &arc_type) {
  IORegistration<VectorFstClass>::Register *reg =
      IORegistration<VectorFstClass>::Register::GetRegister();
  const IORegistration<VectorFstClass>::Entry &entry = reg->GetEntry(arc_type);

  if (entry.converter == 0) {
    LOG(ERROR) << "Unknown arc type " << arc_type;
    return entry;
  }

  return entry;
}

VectorFstClass::VectorFstClass(const FstClass &other)
    : MutableFstClass(GetVFSTRegisterEntry(other.ArcType()).converter(other)) {
}

VectorFstClass::VectorFstClass(const string &arc_type)
    : MutableFstClass(GetVFSTRegisterEntry(arc_type).creator()) { }

VectorFstClass *VectorFstClass::Read(const string &fname) {
  if (!fname.empty()) {
    ifstream in(fname.c_str(), ifstream::in | ifstream::binary);
    return ReadFst<VectorFstClass>(in, fname);
  } else {
    return ReadFst<VectorFstClass>(cin, "standard input");
  }
}

}  // namespace script
}  // namespace fst
