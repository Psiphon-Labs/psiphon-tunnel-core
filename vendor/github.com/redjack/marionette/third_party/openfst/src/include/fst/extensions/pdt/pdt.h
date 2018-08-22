// pdt.h

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
// Common classes for PDT expansion/traversal.

#ifndef FST_EXTENSIONS_PDT_PDT_H__
#define FST_EXTENSIONS_PDT_PDT_H__

#include <unordered_map>
using std::unordered_map;
using std::unordered_multimap;
#include <map>
#include <set>

#include <fst/compat.h>
#include <fst/state-table.h>
#include <fst/fst.h>

namespace fst {

// Provides bijection between parenthesis stacks and signed integral
// stack IDs. Each stack ID is unique to each distinct stack.  The
// open-close parenthesis label pairs are passed in 'parens'.
template <typename K, typename L>
class PdtStack {
 public:
  typedef K StackId;
  typedef L Label;

  // The stacks are stored in a tree. The nodes are stored in vector
  // 'nodes_'. Each node represents the top of some stack and is
  // ID'ed by its position in the vector. Its parent node represents
  // the stack with the top 'popped' and its children are stored in
  // 'child_map_' accessed by stack_id and label. The paren_id is
  // the position in 'parens' of the parenthesis for that node.
  struct StackNode {
    StackId parent_id;
    size_t paren_id;

    StackNode(StackId p, size_t i) : parent_id(p), paren_id(i) {}
  };

  PdtStack(const vector<pair<Label, Label> > &parens)
      : parens_(parens), min_paren_(kNoLabel), max_paren_(kNoLabel) {
    for (size_t i = 0; i < parens.size(); ++i) {
      const pair<Label, Label>  &p = parens[i];
      paren_map_[p.first] = i;
      paren_map_[p.second] = i;

      if (min_paren_ == kNoLabel || p.first < min_paren_)
        min_paren_ = p.first;
      if (p.second < min_paren_)
        min_paren_ = p.second;

      if (max_paren_ == kNoLabel || p.first > max_paren_)
        max_paren_ = p.first;
      if (p.second > max_paren_)
        max_paren_ = p.second;
    }
    nodes_.push_back(StackNode(-1, -1));  // Tree root.
  }

  // Returns stack ID given the current stack ID (0 if empty) and
  // label read. 'Pushes' onto a stack if the label is an open
  // parenthesis, returning the new stack ID. 'Pops' the stack if the
  // label is a close parenthesis that matches the top of the stack,
  // returning the parent stack ID. Returns -1 if label is an
  // unmatched close parenthesis. Otherwise, returns the current stack
  // ID.
  StackId Find(StackId stack_id, Label label) {
    if (min_paren_ == kNoLabel || label < min_paren_ || label > max_paren_)
      return stack_id;                       // Non-paren.

    typename unordered_map<Label, size_t>::const_iterator pit
        = paren_map_.find(label);
    if (pit == paren_map_.end())             // Non-paren.
      return stack_id;
    ssize_t paren_id = pit->second;

    if (label == parens_[paren_id].first) {  // Open paren.
      StackId &child_id = child_map_[make_pair(stack_id, label)];
      if (child_id == 0) {                   // Child not found, push label.
        child_id = nodes_.size();
        nodes_.push_back(StackNode(stack_id, paren_id));
      }
      return child_id;
    }

    const StackNode &node = nodes_[stack_id];
    if (paren_id == node.paren_id)           // Matching close paren.
      return node.parent_id;

    return -1;                               // Non-matching close paren.
  }

  // Returns the stack ID obtained by "popping" the label at the top
  // of the current stack ID.
  StackId Pop(StackId stack_id) const {
    return nodes_[stack_id].parent_id;
  }

  // Returns the paren ID at the top of the stack for 'stack_id'
  ssize_t Top(StackId stack_id) const {
    return nodes_[stack_id].paren_id;
  }

  ssize_t ParenId(Label label) const {
    typename unordered_map<Label, size_t>::const_iterator pit
        = paren_map_.find(label);
    if (pit == paren_map_.end())  // Non-paren.
      return -1;
    return pit->second;
  }

 private:
  struct ChildHash {
    size_t operator()(const pair<StackId, Label> &p) const {
      return p.first + p.second * kPrime;
    }
  };

  static const size_t kPrime;

  vector<pair<Label, Label> > parens_;
  vector<StackNode> nodes_;
  unordered_map<Label, size_t> paren_map_;
  unordered_map<pair<StackId, Label>,
           StackId, ChildHash> child_map_;   // Child of stack node wrt label
  Label min_paren_;                          // For faster paren. check
  Label max_paren_;                          // For faster paren. check
};

template <typename T, typename L>
const size_t PdtStack<T, L>::kPrime = 7853;


// State tuple for PDT expansion
template <typename S, typename K>
struct PdtStateTuple {
  typedef S StateId;
  typedef K StackId;

  StateId state_id;
  StackId stack_id;

  PdtStateTuple()
      : state_id(kNoStateId), stack_id(-1) {}

  PdtStateTuple(StateId fs, StackId ss)
      : state_id(fs), stack_id(ss) {}
};

// Equality of PDT state tuples.
template <typename S, typename K>
inline bool operator==(const PdtStateTuple<S, K>& x,
                       const PdtStateTuple<S, K>& y) {
  if (&x == &y)
    return true;
  return x.state_id == y.state_id && x.stack_id == y.stack_id;
}


// Hash function object for PDT state tuples
template <class T>
class PdtStateHash {
 public:
  size_t operator()(const T &tuple) const {
    return tuple.state_id + tuple.stack_id * kPrime;
  }

 private:
  static const size_t kPrime;
};

template <typename T>
const size_t PdtStateHash<T>::kPrime = 7853;


// Tuple to PDT state bijection.
template <class S, class K>
class PdtStateTable
    : public CompactHashStateTable<PdtStateTuple<S, K>,
                                   PdtStateHash<PdtStateTuple<S, K> > > {
 public:
  typedef S StateId;
  typedef K StackId;

  PdtStateTable() {}

  PdtStateTable(const PdtStateTable<S, K> &table) {}

 private:
  void operator=(const PdtStateTable<S, K> &table);  // disallow
};

}  // namespace fst

#endif  // FST_EXTENSIONS_PDT_PDT_H__
