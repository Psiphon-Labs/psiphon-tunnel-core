
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

// Represents a generic weight in an FST -- that is, represents a specific
// type of weight underneath while hiding that type from a client.


#ifndef FST_SCRIPT_WEIGHT_CLASS_H_
#define FST_SCRIPT_WEIGHT_CLASS_H_

#include <string>

#include <fst/generic-register.h>
#include <fst/util.h>

namespace fst {
namespace script {

class WeightImplBase {
 public:
  virtual WeightImplBase *Copy() const = 0;
  virtual void Print(ostream *o) const = 0;
  virtual const string &Type() const = 0;
  virtual string to_string() const = 0;
  virtual bool operator == (const WeightImplBase &other) const = 0;
  virtual ~WeightImplBase() { }
};

template<class W>
struct WeightClassImpl : public WeightImplBase {
  W weight;

  explicit WeightClassImpl(const W& weight) : weight(weight) { }

  virtual WeightClassImpl<W> *Copy() const {
    return new WeightClassImpl<W>(weight);
  }

  virtual const string &Type() const { return W::Type(); }

  virtual void Print(ostream *o) const {
    *o << weight;
  }

  virtual string to_string() const {
    string str;
    WeightToStr(weight, &str);
    return str;
  }

  virtual bool operator == (const WeightImplBase &other) const {
    if (Type() != other.Type()) {
      return false;
    } else {
      const WeightClassImpl<W> *typed_other =
          static_cast<const WeightClassImpl<W> *>(&other);

      return typed_other->weight == weight;
    }
  }
};


class WeightClass {
 public:
  WeightClass() : element_type_(ZERO), impl_(0) { }

  template<class W>
  explicit WeightClass(const W& weight)
  : element_type_(OTHER), impl_(new WeightClassImpl<W>(weight)) { }

  WeightClass(const string &weight_type, const string &weight_str);

  WeightClass(const WeightClass &other) :
      element_type_(other.element_type_),
      impl_(other.impl_ ? other.impl_->Copy() : 0) { }

  WeightClass &operator = (const WeightClass &other) {
    if (impl_) delete impl_;
    impl_ = other.impl_ ? other.impl_->Copy() : 0;
    element_type_ = other.element_type_;
    return *this;
  }

  template<class W>
  const W* GetWeight() const;

  string to_string() const {
    switch (element_type_) {
      case ZERO:
        return "ZERO";
      case ONE:
        return "ONE";
      default:
      case OTHER:
        return impl_->to_string();
    }
  }

  bool operator == (const WeightClass &other) const {
    return element_type_ == other.element_type_ &&
        ((impl_ && other.impl_ && (*impl_ == *other.impl_)) ||
         (impl_ == 0 && other.impl_ == 0));
  }

  static const WeightClass &Zero() {
    static WeightClass w(ZERO);

    return w;
  }

  static const WeightClass &One() {
    static WeightClass w(ONE);

    return w;
  }

  const string &Type() const {
    if (impl_) return impl_->Type();
    static const string no_type = "none";
    return no_type;
  }


  ~WeightClass() { if (impl_) delete impl_; }
 private:
  enum ElementType { ZERO, ONE, OTHER };
  ElementType element_type_;

  WeightImplBase *impl_;

  explicit WeightClass(ElementType et) : element_type_(et), impl_(0) { }

  friend ostream &operator << (ostream &o, const WeightClass &c);
};

template<class W>
const W* WeightClass::GetWeight() const {
  // We need to store zero and one as statics, because the weight type
  // W might return them as temporaries. We're returning a pointer,
  // and it won't do to get the address of a temporary.
  static const W zero = W::Zero();
  static const W one = W::One();

  if (element_type_ == ZERO) {
    return &zero;
  } else if (element_type_ == ONE) {
    return &one;
  } else {
    if (W::Type() != impl_->Type()) {
      return NULL;
    } else {
      WeightClassImpl<W> *typed_impl =
          static_cast<WeightClassImpl<W> *>(impl_);
      return &typed_impl->weight;
    }
  }
}

//
// Registration for generic weight types.
//

typedef WeightImplBase* (*StrToWeightImplBaseT)(const string &str,
                                                const string &src,
                                                size_t nline);

template<class W>
WeightImplBase* StrToWeightImplBase(const string &str,
                                    const string &src, size_t nline) {
  return new WeightClassImpl<W>(StrToWeight<W>(str, src, nline));
}

// The following confuses swig, and doesn't need to be wrapped anyway.
#ifndef SWIG
ostream& operator << (ostream &o, const WeightClass &c);

class WeightClassRegister : public GenericRegister<string,
                                                   StrToWeightImplBaseT,
                                                   WeightClassRegister> {
 protected:
  virtual string ConvertKeyToSoFilename(const string &key) const {
    return key + ".so";
  }
};

typedef GenericRegisterer<WeightClassRegister> WeightClassRegisterer;
#endif

// internal version, needs to be called by wrapper in order for
// macro args to expand
#define REGISTER_FST_WEIGHT__(Weight, line)                             \
  static WeightClassRegisterer weight_registerer ## _ ## line(          \
      Weight::Type(),                                                   \
      StrToWeightImplBase<Weight>)

// This layer is where __FILE__ and __LINE__ are expanded
#define REGISTER_FST_WEIGHT_EXPANDER(Weight, line)      \
  REGISTER_FST_WEIGHT__(Weight, line)

//
// Macro for registering new weight types. Clients call this.
//
#define REGISTER_FST_WEIGHT(Weight) \
  REGISTER_FST_WEIGHT_EXPANDER(Weight, __LINE__)

}  // namespace script
}  // namespace fst

#endif  // FST_SCRIPT_WEIGHT_CLASS_H_
