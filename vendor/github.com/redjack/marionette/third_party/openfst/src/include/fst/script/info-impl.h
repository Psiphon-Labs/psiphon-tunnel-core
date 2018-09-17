// info.h

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
// Class to compute various information about FSTs, helper class for fstinfo.cc

#ifndef FST_SCRIPT_INFO_IMPL_H_
#define FST_SCRIPT_INFO_IMPL_H_

#include <map>
#include <string>
#include <vector>
using std::vector;

#include <fst/connect.h>
#include <fst/dfs-visit.h>
#include <fst/fst.h>
#include <fst/lookahead-matcher.h>
#include <fst/matcher.h>
#include <fst/queue.h>
#include <fst/test-properties.h>
#include <fst/verify.h>
#include <fst/visit.h>

namespace fst {

// Compute various information about FSTs, helper class for fstinfo.cc.
// WARNING: Stand-alone use of this class is not recommended, most code
// should call directly the relevant library functions: Fst<A>::NumStates,
// Fst<A>::NumArcs, TestProperties, ...
template <class A> class FstInfo {
 public:
  typedef A Arc;
  typedef typename A::StateId StateId;
  typedef typename A::Label Label;
  typedef typename A::Weight Weight;

  // When info_type is "short" (or "auto" and not an ExpandedFst)
  // then only minimal info is computed and can be requested.
  FstInfo(const Fst<A> &fst, bool test_properties,
          const string &arc_filter_type = "any",
          string info_type = "auto", bool verify = true)
      : fst_type_(fst.Type()),
        input_symbols_(fst.InputSymbols() ?
                       fst.InputSymbols()->Name() : "none"),
        output_symbols_(fst.OutputSymbols() ?
                        fst.OutputSymbols()->Name() : "none"),
        nstates_(0), narcs_(0), start_(kNoStateId), nfinal_(0),
        nepsilons_(0), niepsilons_(0), noepsilons_(0),
        ilabel_mult_(0.0), olabel_mult_(0.0),
        naccess_(0), ncoaccess_(0), nconnect_(0), ncc_(0), nscc_(0),
        input_match_type_(MATCH_NONE), output_match_type_(MATCH_NONE),
        input_lookahead_(false), output_lookahead_(false),
        properties_(0), arc_filter_type_(arc_filter_type), long_info_(true) {
    if (info_type == "long") {
      long_info_ = true;
    } else if (info_type == "short") {
      long_info_ = false;
    } else if (info_type == "auto") {
      long_info_ = fst.Properties(kExpanded, false);
    } else {
      FSTERROR() << "Bad info type: " << info_type;
      return;
    }

    if (!long_info_)
      return;

    // If the FST is not sane, we return.
    if (verify && !Verify(fst)) {
      FSTERROR() << "FstInfo: Verify: FST not well-formed.";
      return;
    }

    start_ = fst.Start();
    properties_ = fst.Properties(kFstProperties, test_properties);

    for (StateIterator< Fst<A> > siter(fst);
         !siter.Done();
         siter.Next()) {
      ++nstates_;
      StateId s = siter.Value();
      if (fst.Final(s) != Weight::Zero())
        ++nfinal_;
      map<Label, int64> ilabel_count;
      map<Label, int64> olabel_count;
      for (ArcIterator< Fst<A> > aiter(fst, s);
           !aiter.Done();
           aiter.Next()) {
        const A &arc = aiter.Value();
        ++narcs_;
        if (arc.ilabel == 0 && arc.olabel == 0)
          ++nepsilons_;
        if (arc.ilabel == 0)
          ++niepsilons_;
        if (arc.olabel == 0)
          ++noepsilons_;
        ++ilabel_count[arc.ilabel];
        ++olabel_count[arc.olabel];
      }
      for (typename map<Label, int64>::iterator it = ilabel_count.begin();
           it != ilabel_count.end();
           ++it) {
        ilabel_mult_ += it->second * it->second;
      }
      for (typename map<Label, int64>::iterator it = olabel_count.begin();
           it != olabel_count.end();
           ++it) {
        olabel_mult_ += it->second * it->second;
      }
    }

    if (narcs_ > 0) {
      ilabel_mult_ /= narcs_;
      olabel_mult_ /= narcs_;
    }

    {
      vector<StateId> cc;
      CcVisitor<Arc> cc_visitor(&cc);
      FifoQueue<StateId> fifo_queue;
      if (arc_filter_type == "any") {
        Visit(fst, &cc_visitor, &fifo_queue);
      } else if (arc_filter_type == "epsilon") {
        Visit(fst, &cc_visitor, &fifo_queue, EpsilonArcFilter<Arc>());
      } else if (arc_filter_type == "iepsilon") {
        Visit(fst, &cc_visitor, &fifo_queue, InputEpsilonArcFilter<Arc>());
      } else if (arc_filter_type == "oepsilon") {
        Visit(fst, &cc_visitor, &fifo_queue, OutputEpsilonArcFilter<Arc>());
      } else {
        FSTERROR() << "Bad arc filter type: " << arc_filter_type;
        return;
      }

      for (StateId s = 0; s < cc.size(); ++s) {
        if (cc[s] >= ncc_)
          ncc_ = cc[s] + 1;
      }
    }

    {
      vector<StateId> scc;
      vector<bool> access, coaccess;
      uint64 props = 0;
      SccVisitor<Arc> scc_visitor(&scc, &access, &coaccess, &props);
      if (arc_filter_type == "any") {
        DfsVisit(fst, &scc_visitor);
      } else if (arc_filter_type == "epsilon") {
        DfsVisit(fst, &scc_visitor, EpsilonArcFilter<Arc>());
      } else if (arc_filter_type == "iepsilon") {
        DfsVisit(fst, &scc_visitor, InputEpsilonArcFilter<Arc>());
      } else if (arc_filter_type == "oepsilon") {
        DfsVisit(fst, &scc_visitor, OutputEpsilonArcFilter<Arc>());
      } else {
        FSTERROR() << "Bad arc filter type: " << arc_filter_type;
        return;
      }

      for (StateId s = 0; s < scc.size(); ++s) {
        if (access[s])
          ++naccess_;
        if (coaccess[s])
          ++ncoaccess_;
        if (access[s] && coaccess[s])
          ++nconnect_;
        if (scc[s] >= nscc_)
          nscc_ = scc[s] + 1;
      }
    }

    LookAheadMatcher< Fst<A> > imatcher(fst, MATCH_INPUT);
    input_match_type_ =  imatcher.Type(test_properties);
    input_lookahead_ =  imatcher.Flags() & kInputLookAheadMatcher;

    LookAheadMatcher< Fst<A> > omatcher(fst, MATCH_OUTPUT);
    output_match_type_ =  omatcher.Type(test_properties);
    output_lookahead_ =  omatcher.Flags() & kOutputLookAheadMatcher;
  }

  // Short info
  const string& FstType() const { return fst_type_; }
  const string& ArcType() const { return A::Type(); }
  const string& InputSymbols() const { return input_symbols_; }
  const string& OutputSymbols() const { return output_symbols_; }
  bool LongInfo() const { return long_info_; }
  const string& ArcFilterType() const { return arc_filter_type_; }

  // Long info
  MatchType InputMatchType() const { CheckLong(); return input_match_type_; }
  MatchType OutputMatchType() const { CheckLong(); return output_match_type_; }
  bool InputLookAhead() const { CheckLong(); return input_lookahead_; }
  bool OutputLookAhead() const { CheckLong();  return output_lookahead_; }
  int64 NumStates() const { CheckLong();  return nstates_; }
  int64 NumArcs() const { CheckLong();  return narcs_; }
  int64 Start() const { CheckLong();  return start_; }
  int64 NumFinal() const { CheckLong();  return nfinal_; }
  int64 NumEpsilons() const { CheckLong();  return nepsilons_; }
  int64 NumInputEpsilons() const { CheckLong(); return niepsilons_; }
  int64 NumOutputEpsilons() const { CheckLong(); return noepsilons_; }
  double InputLabelMultiplicity() const { CheckLong(); return ilabel_mult_; }
  double OutputLabelMultiplicity() const { CheckLong(); return olabel_mult_; }

  int64 NumAccessible() const { CheckLong(); return naccess_; }
  int64 NumCoAccessible() const { CheckLong(); return ncoaccess_; }
  int64 NumConnected() const { CheckLong(); return nconnect_; }
  int64 NumCc() const { CheckLong(); return ncc_; }
  int64 NumScc() const { CheckLong(); return nscc_; }
  uint64 Properties() const { CheckLong(); return properties_; }

 private:
  void CheckLong() const {
    if (!long_info_)
      FSTERROR() << "FstInfo: method only available with long info version";
  }

  string fst_type_;
  string input_symbols_;
  string output_symbols_;
  int64 nstates_;
  int64 narcs_;
  int64 start_;
  int64 nfinal_;
  int64 nepsilons_;
  int64 niepsilons_;
  int64 noepsilons_;
  double ilabel_mult_;
  double olabel_mult_;
  int64 naccess_;
  int64 ncoaccess_;
  int64 nconnect_;
  int64 ncc_;
  int64 nscc_;
  MatchType input_match_type_;
  MatchType output_match_type_;
  bool input_lookahead_;
  bool output_lookahead_;
  uint64 properties_;
  string arc_filter_type_;
  bool long_info_;
  DISALLOW_COPY_AND_ASSIGN(FstInfo);
};

template <class A>
void PrintFstInfo(const FstInfo<A> &fstinfo, bool pipe = false) {
  ostream &os = pipe ? cerr : cout;

  ios_base::fmtflags old = os.setf(ios::left);
  os.width(50);
  os << "fst type" <<  fstinfo.FstType() << endl;
  os.width(50);
  os << "arc type" << fstinfo.ArcType() << endl;
  os.width(50);
  os << "input symbol table" << fstinfo.InputSymbols() << endl;
  os.width(50);
  os << "output symbol table" << fstinfo.OutputSymbols() << endl;

  if (!fstinfo.LongInfo()) {
    os.setf(old);
    return;
  }

  os.width(50);
  os << "# of states" << fstinfo.NumStates() << endl;
  os.width(50);
  os << "# of arcs" << fstinfo.NumArcs() << endl;
  os.width(50);
  os << "initial state" << fstinfo.Start() << endl;
  os.width(50);
  os << "# of final states" << fstinfo.NumFinal() << endl;
  os.width(50);
  os << "# of input/output epsilons" << fstinfo.NumEpsilons() << endl;
  os.width(50);
  os << "# of input epsilons" << fstinfo.NumInputEpsilons() << endl;
  os.width(50);
  os << "# of output epsilons" << fstinfo.NumOutputEpsilons() << endl;
  os.width(50);
  os << "input label multiplicity" << fstinfo.InputLabelMultiplicity() << endl;
  os.width(50);
  os << "output label multiplicity" << fstinfo.OutputLabelMultiplicity() << endl;
  os.width(50);

  string arc_type = "";
  if (fstinfo.ArcFilterType() == "epsilon")
    arc_type = "epsilon ";
  else if (fstinfo.ArcFilterType() == "iepsilon")
    arc_type = "input-epsilon ";
  else if (fstinfo.ArcFilterType() == "oepsilon")
    arc_type = "output-epsilon ";

  string accessible_label = "# of " +  arc_type + "accessible states";
  os.width(50);
  os << accessible_label << fstinfo.NumAccessible() << endl;
  string coaccessible_label = "# of " +  arc_type + "coaccessible states";
  os.width(50);
  os << coaccessible_label << fstinfo.NumCoAccessible() << endl;
  string connected_label = "# of " +  arc_type + "connected states";
  os.width(50);
  os << connected_label << fstinfo.NumConnected() << endl;
  string numcc_label = "# of " +  arc_type + "connected components";
  os.width(50);
  os << numcc_label << fstinfo.NumCc() << endl;
  string numscc_label = "# of " +  arc_type + "strongly conn components";
  os.width(50);
  os << numscc_label << fstinfo.NumScc() << endl;

  os.width(50);
  os << "input matcher"
     << (fstinfo.InputMatchType() == MATCH_INPUT ? 'y' :
         fstinfo.InputMatchType() == MATCH_NONE ? 'n' : '?') << endl;
  os.width(50);
  os << "output matcher"
     << (fstinfo.OutputMatchType() == MATCH_OUTPUT ? 'y' :
         fstinfo.OutputMatchType() == MATCH_NONE ? 'n' : '?') << endl;
  os.width(50);
  os << "input lookahead"
     << (fstinfo.InputLookAhead() ? 'y' : 'n') << endl;
  os.width(50);
  os << "output lookahead"
     << (fstinfo.OutputLookAhead() ? 'y' : 'n') << endl;

  uint64 prop = 1;
  for (int i = 0; i < 64; ++i, prop <<= 1) {
    if (prop & kBinaryProperties) {
      char value = 'n';
      if (fstinfo.Properties() & prop) value = 'y';
      os.width(50);
      os << PropertyNames[i] << value << endl;
    } else if (prop & kPosTrinaryProperties) {
      char value = '?';
      if (fstinfo.Properties() & prop) value = 'y';
      else if (fstinfo.Properties() & prop << 1) value = 'n';
      os.width(50);
      os << PropertyNames[i] << value << endl;
    }
  }
  os.setf(old);
}

}  // namespace fst

#endif  // FST_SCRIPT_INFO_IMPL_H_
