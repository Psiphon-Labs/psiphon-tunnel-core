
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

#ifndef FST_SCRIPT_FST_CLASS_H_
#define FST_SCRIPT_FST_CLASS_H_

#include <string>

#include <fst/fst.h>
#include <fst/mutable-fst.h>
#include <fst/vector-fst.h>
#include <iostream>
#include <fstream>
#include <sstream>

// Classes to support "boxing" all existing types of FST arcs in a single
// FstClass which hides the arc types. This allows clients to load
// and work with FSTs without knowing the arc type.

// These classes are only recommended for use in high-level scripting
// applications. Most users should use the lower-level templated versions
// corresponding to these classes.

namespace fst {
namespace script {

//
// Abstract base class defining the set of functionalities implemented
// in all impls, and passed through by all bases Below FstClassBase
// the class hierarchy bifurcates; FstClassImplBase serves as the base
// class for all implementations (of which FstClassImpl is currently
// the only one) and FstClass serves as the base class for all
// interfaces.
//
class FstClassBase {
 public:
  virtual const string &ArcType() const = 0;
  virtual const string &FstType() const = 0;
  virtual const string &WeightType() const = 0;
  virtual const SymbolTable *InputSymbols() const = 0;
  virtual const SymbolTable *OutputSymbols() const = 0;
  virtual bool Write(const string& fname) const = 0;
  virtual bool Write(ostream &ostr, const FstWriteOptions &opts) const = 0;
  virtual uint64 Properties(uint64 mask, bool test) const = 0;
  virtual ~FstClassBase() { }
};

class FstClassImplBase : public FstClassBase {
 public:
  virtual FstClassImplBase *Copy() = 0;
  virtual void SetInputSymbols(SymbolTable *is) = 0;
  virtual void SetOutputSymbols(SymbolTable *is) = 0;
  virtual ~FstClassImplBase() { }
};


//
// CONTAINER CLASS
// Wraps an Fst<Arc>, hiding its arc type. Whether this Fst<Arc>
// pointer refers to a special kind of FST (e.g. a MutableFst) is
// known by the type of interface class that owns the pointer to this
// container.
//

template<class Arc>
class FstClassImpl : public FstClassImplBase {
 public:
  explicit FstClassImpl(Fst<Arc> *impl,
                        bool should_own = false) :
      impl_(should_own ? impl : impl->Copy()) { }

  explicit FstClassImpl(const Fst<Arc> &impl) : impl_(impl.Copy()) {  }

  virtual const string &ArcType() const {
    return Arc::Type();
  }

  virtual const string &FstType() const {
    return impl_->Type();
  }

  virtual const string &WeightType() const {
    return Arc::Weight::Type();
  }

  virtual const SymbolTable *InputSymbols() const {
    return impl_->InputSymbols();
  }

  virtual const SymbolTable *OutputSymbols() const {
    return impl_->OutputSymbols();
  }

  // Warning: calling this method casts the FST to a mutable FST.
  virtual void SetInputSymbols(SymbolTable *is) {
    static_cast<MutableFst<Arc> *>(impl_)->SetInputSymbols(is);
  }

  // Warning: calling this method casts the FST to a mutable FST.
  virtual void SetOutputSymbols(SymbolTable *os) {
    static_cast<MutableFst<Arc> *>(impl_)->SetOutputSymbols(os);
  }

  virtual bool Write(const string &fname) const {
    return impl_->Write(fname);
  }

  virtual bool Write(ostream &ostr, const FstWriteOptions &opts) const {
    return impl_->Write(ostr, opts);
  }

  virtual uint64 Properties(uint64 mask, bool test) const {
    return impl_->Properties(mask, test);
  }

  virtual ~FstClassImpl() { delete impl_; }

  Fst<Arc> *GetImpl() const { return impl_; }

  Fst<Arc> *GetImpl() { return impl_; }

  virtual FstClassImpl *Copy() {
    return new FstClassImpl<Arc>(impl_);
  }

 private:
  Fst<Arc> *impl_;
};

//
// BASE CLASS DEFINITIONS
//

class MutableFstClass;

class FstClass : public FstClassBase {
 public:
  template<class Arc>
  static FstClass *Read(istream &stream,
                        const FstReadOptions &opts) {
    if (!opts.header) {
      FSTERROR() << "FstClass::Read: options header not specified";
      return 0;
    }
    const FstHeader &hdr = *opts.header;

    if (hdr.Properties() & kMutable) {
      return ReadTypedFst<MutableFstClass, MutableFst<Arc> >(stream, opts);
    } else {
      return ReadTypedFst<FstClass, Fst<Arc> >(stream, opts);
    }
  }

  FstClass() : impl_(NULL) {
  }

  template<class Arc>
  explicit FstClass(const Fst<Arc> &fst) : impl_(new FstClassImpl<Arc>(fst)) {
  }

  FstClass(const FstClass &other) : impl_(other.impl_->Copy()) { }

  FstClass &operator=(const FstClass &other) {
    delete impl_;
    impl_ = other.impl_->Copy();
    return *this;
  }

  static FstClass *Read(const string &fname);

  static FstClass *Read(istream &istr, const string &source);

  virtual const string &ArcType() const {
    return impl_->ArcType();
  }

  virtual const string& FstType() const {
    return impl_->FstType();
  }

  virtual const SymbolTable *InputSymbols() const {
    return impl_->InputSymbols();
  }

  virtual const SymbolTable *OutputSymbols() const {
    return impl_->OutputSymbols();
  }

  virtual const string& WeightType() const {
    return impl_->WeightType();
  }

  virtual bool Write(const string &fname) const {
    return impl_->Write(fname);
  }

  virtual bool Write(ostream &ostr, const FstWriteOptions &opts) const {
    return impl_->Write(ostr, opts);
  }

  virtual uint64 Properties(uint64 mask, bool test) const {
    return impl_->Properties(mask, test);
  }

  template<class Arc>
  const Fst<Arc> *GetFst() const {
    if (Arc::Type() != ArcType()) {
      return NULL;
    } else {
      FstClassImpl<Arc> *typed_impl = static_cast<FstClassImpl<Arc> *>(impl_);
      return typed_impl->GetImpl();
    }
  }

  virtual ~FstClass() { delete impl_; }

  // These methods are required by IO registration
  template<class Arc>
  static FstClassImplBase *Convert(const FstClass &other) {
    LOG(ERROR) << "Doesn't make sense to convert any class to type FstClass.";
    return 0;
  }

  template<class Arc>
  static FstClassImplBase *Create() {
    LOG(ERROR) << "Doesn't make sense to create an FstClass with a "
               << "particular arc type.";
    return 0;
  }


 protected:
  explicit FstClass(FstClassImplBase *impl) : impl_(impl) { }

  // Generic template method for reading an arc-templated FST of type
  // UnderlyingT, and returning it wrapped as FstClassT, with appropriate
  // error checking. Called from arc-templated Read() static methods.
  template<class FstClassT, class UnderlyingT>
  static FstClassT* ReadTypedFst(istream &stream,
                                     const FstReadOptions &opts) {
    UnderlyingT *u = UnderlyingT::Read(stream, opts);
    if (!u) {
      return 0;
    } else {
      FstClassT *r = new FstClassT(*u);
      delete u;
      return r;
    }
  }

  FstClassImplBase *GetImpl() const { return impl_; }

  FstClassImplBase *GetImpl() { return impl_; }

//  friend ostream &operator<<(ostream&, const FstClass&);

 private:
  FstClassImplBase *impl_;
};

//
// Specific types of FstClass with special properties
//

class MutableFstClass : public FstClass {
 public:
  template<class Arc>
  explicit MutableFstClass(const MutableFst<Arc> &fst) :
      FstClass(fst) { }

  template<class Arc>
  MutableFst<Arc> *GetMutableFst() {
    Fst<Arc> *fst = const_cast<Fst<Arc> *>(this->GetFst<Arc>());
    MutableFst<Arc> *mfst = static_cast<MutableFst<Arc> *>(fst);

    return mfst;
  }

  template<class Arc>
  static MutableFstClass *Read(istream &stream,
                               const FstReadOptions &opts) {
    MutableFst<Arc> *mfst = MutableFst<Arc>::Read(stream, opts);
    if (!mfst) {
      return 0;
    } else {
      MutableFstClass *retval = new MutableFstClass(*mfst);
      delete mfst;
      return retval;
    }
  }

  virtual bool Write(const string &fname) const {
    return GetImpl()->Write(fname);
  }

  virtual bool Write(ostream &ostr, const FstWriteOptions &opts) const {
    return GetImpl()->Write(ostr, opts);
  }

  static MutableFstClass *Read(const string &fname, bool convert = false);

  virtual void SetInputSymbols(SymbolTable *is) {
    GetImpl()->SetInputSymbols(is);
  }

  virtual void SetOutputSymbols(SymbolTable *os) {
    GetImpl()->SetOutputSymbols(os);
  }

  // These methods are required by IO registration
  template<class Arc>
  static FstClassImplBase *Convert(const FstClass &other) {
    LOG(ERROR) << "Doesn't make sense to convert any class to type "
               << "MutableFstClass.";
    return 0;
  }

  template<class Arc>
  static FstClassImplBase *Create() {
    LOG(ERROR) << "Doesn't make sense to create a MutableFstClass with a "
               << "particular arc type.";
    return 0;
  }

 protected:
  explicit MutableFstClass(FstClassImplBase *impl) : FstClass(impl) { }
};


class VectorFstClass : public MutableFstClass {
 public:
  explicit VectorFstClass(const FstClass &other);
  explicit VectorFstClass(const string &arc_type);

  template<class Arc>
  explicit VectorFstClass(const VectorFst<Arc> &fst) :
      MutableFstClass(fst) { }

  template<class Arc>
  static VectorFstClass *Read(istream &stream,
                              const FstReadOptions &opts) {
    VectorFst<Arc> *vfst = VectorFst<Arc>::Read(stream, opts);
    if (!vfst) {
      return 0;
    } else {
      VectorFstClass *retval = new VectorFstClass(*vfst);
      delete vfst;
      return retval;
    }
  }

  static VectorFstClass *Read(const string &fname);

  // Converter / creator for known arc types
  template<class Arc>
  static FstClassImplBase *Convert(const FstClass &other) {
    return new FstClassImpl<Arc>(new VectorFst<Arc>(
        *other.GetFst<Arc>()), true);
  }

  template<class Arc>
  static FstClassImplBase *Create() {
    return new FstClassImpl<Arc>(new VectorFst<Arc>(), true);
  }
};

}  // namespace script
}  // namespace fst
#endif  // FST_SCRIPT_FST_CLASS_H_
