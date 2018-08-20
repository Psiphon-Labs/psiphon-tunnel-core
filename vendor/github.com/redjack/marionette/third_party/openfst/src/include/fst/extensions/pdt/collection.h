// collection.h

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
// Class to store a collection of ordered (multi-)sets with elements of type T.

#ifndef FST_EXTENSIONS_PDT_COLLECTION_H__
#define FST_EXTENSIONS_PDT_COLLECTION_H__

#include <algorithm>
#include <vector>
using std::vector;

#include <fst/bi-table.h>

namespace fst {

// Stores a collection of non-empty, ordered (multi-)sets with elements
// of type T. A default constructor, equality ==, and an STL-style
// hash class must be defined on the elements. Provides signed integer
// ID (of type I) of each unique set. The IDs are allocated starting
// from 0 in order.
template <class I, class T>
class Collection {
 public:
  struct Node {  // Trie node
    I node_id;   // Root is kNoNodeId;
    T element;

    Node() : node_id(kNoNodeId), element(T()) {}
    Node(I i, const T &t) : node_id(i), element(t) {}

    bool operator==(const Node& n) const {
      return n.node_id == node_id && n.element == element;
    }
  };

  struct NodeHash {
    size_t operator()(const Node &n) const {
      return n.node_id + hash_(n.element) * kPrime;
    }
  };

  typedef CompactHashBiTable<I, Node, NodeHash> NodeTable;

  class SetIterator {
   public:
    SetIterator(I id, Node node, NodeTable *node_table)
        :id_(id), node_(node), node_table_(node_table) {}

    bool Done() const { return id_ == kNoNodeId; }

    const T &Element() const { return node_.element; }

    void Next() {
      id_ = node_.node_id;
      if (id_ != kNoNodeId)
        node_ = node_table_->FindEntry(id_);
    }

   private:
    I id_;                     // Iterator set node id
    Node node_;                // Iterator set node
    NodeTable *node_table_;
  };

  Collection() {}

  // Lookups integer ID from ordered multi-set. If it doesn't exist
  // and 'insert' is true, then adds it. Otherwise returns -1.
  I FindId(const vector<T> &set, bool insert = true) {
    I node_id = kNoNodeId;
    for (ssize_t i = set.size() - 1; i >= 0; --i) {
      Node node(node_id, set[i]);
      node_id = node_table_.FindId(node, insert);
      if (node_id == -1) break;
    }
    return node_id;
  }

  // Finds ordered (multi-)set given integer ID. Returns set iterator
  // to traverse result.
  SetIterator FindSet(I id) {
    if (id < 0 || id >= node_table_.Size()) {
      return SetIterator(kNoNodeId, Node(kNoNodeId, T()), &node_table_);
    } else {
      return SetIterator(id, node_table_.FindEntry(id), &node_table_);
    }
  }

  I Size() const { return node_table_.Size(); }

 private:
  static const I kNoNodeId;
  static const size_t kPrime;
  static std::hash<T> hash_;

  NodeTable node_table_;

  DISALLOW_COPY_AND_ASSIGN(Collection);
};

template<class I, class T> const I Collection<I, T>::kNoNodeId = -1;

template <class I, class T> const size_t Collection<I, T>::kPrime = 7853;

template <class I, class T> std::hash<T> Collection<I, T>::hash_;

}  // namespace fst

#endif  // FST_EXTENSIONS_PDT_COLLECTION_H__
