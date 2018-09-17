
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
// Author: allauzen@google.com (Cyril Allauzen)
//
// \file
// A generic (string,type) list file format.
//
// This is a stripped-down version of STTable that does
// not support the Find() operation but that does support
// reading/writting from standard in/out.

#ifndef FST_EXTENSIONS_FAR_STLIST_H_
#define FST_EXTENSIONS_FAR_STLIST_H_

#include <iostream>
#include <fstream>
#include <sstream>
#include <fst/util.h>

#include <algorithm>
#include <functional>
#include <queue>
#include <string>
#include <utility>
using std::pair; using std::make_pair;
#include <vector>
using std::vector;

namespace fst {

static const int32 kSTListMagicNumber = 5656924;
static const int32 kSTListFileVersion = 1;

// String-type list writing class for object of type 'T' using functor 'W'
// to write an object of type 'T' from a stream. 'W' must conform to the
// following interface:
//
//   struct Writer {
//     void operator()(ostream &, const T &) const;
//   };
//
template <class T, class W>
class STListWriter {
 public:
  typedef T EntryType;
  typedef W EntryWriter;

  explicit STListWriter(const string filename)
      : stream_(
          filename.empty() ? &cout :
          new ofstream(filename.c_str(), ofstream::out | ofstream::binary)),
        error_(false) {
    WriteType(*stream_, kSTListMagicNumber);
    WriteType(*stream_, kSTListFileVersion);
    if (!stream_) {
      FSTERROR() << "STListWriter::STListWriter: error writing to file: "
                 << filename;
      error_ = true;
    }
  }

  static STListWriter<T, W> *Create(const string &filename) {
    return new STListWriter<T, W>(filename);
  }

  void Add(const string &key, const T &t) {
    if (key == "") {
      FSTERROR() << "STListWriter::Add: key empty: " << key;
      error_ = true;
    } else if (key < last_key_) {
      FSTERROR() << "STListWriter::Add: key disorder: " << key;
      error_ = true;
    }
    if (error_) return;
    last_key_ = key;
    WriteType(*stream_, key);
    entry_writer_(*stream_, t);
  }

  bool Error() const { return error_; }

  ~STListWriter() {
    WriteType(*stream_, string());
    if (stream_ != &cout)
      delete stream_;
  }

 private:
  EntryWriter entry_writer_;  // Write functor for 'EntryType'
  ostream *stream_;           // Output stream
  string last_key_;           // Last key
  bool error_;

  DISALLOW_COPY_AND_ASSIGN(STListWriter);
};


// String-type list reading class for object of type 'T' using functor 'R'
// to read an object of type 'T' form a stream. 'R' must conform to the
// following interface:
//
//   struct Reader {
//     T *operator()(istream &) const;
//   };
//
template <class T, class R>
class STListReader {
 public:
  typedef T EntryType;
  typedef R EntryReader;

  explicit STListReader(const vector<string> &filenames)
      : sources_(filenames), entry_(0), error_(false) {
    streams_.resize(filenames.size(), 0);
    bool has_stdin = false;
    for (size_t i = 0; i < filenames.size(); ++i) {
      if (filenames[i].empty()) {
        if (!has_stdin) {
          streams_[i] = &cin;
          sources_[i] = "stdin";
          has_stdin = true;
        } else {
          FSTERROR() << "STListReader::STListReader: stdin should only "
                     << "appear once in the input file list.";
          error_ = true;
          return;
        }
      } else {
        streams_[i] = new ifstream(
            filenames[i].c_str(), ifstream::in | ifstream::binary);
      }
      int32 magic_number = 0, file_version = 0;
      ReadType(*streams_[i], &magic_number);
      ReadType(*streams_[i], &file_version);
      if (magic_number != kSTListMagicNumber) {
        FSTERROR() << "STListReader::STListReader: wrong file type: "
                   << filenames[i];
        error_ = true;
        return;
      }
      if (file_version != kSTListFileVersion) {
        FSTERROR() << "STListReader::STListReader: wrong file version: "
                   << filenames[i];
        error_ = true;
        return;
      }
      string key;
      ReadType(*streams_[i], &key);
      if (!key.empty())
        heap_.push(make_pair(key, i));
      if (!*streams_[i]) {
        FSTERROR() << "STListReader: error reading file: " << sources_[i];
        error_ = true;
        return;
      }
    }
    if (heap_.empty()) return;
    size_t current = heap_.top().second;
    entry_ = entry_reader_(*streams_[current]);
    if (!entry_ || !*streams_[current]) {
      FSTERROR() << "STListReader: error reading entry for key: "
                 << heap_.top().first << ", file: " << sources_[current];
      error_ = true;
    }
  }

  ~STListReader() {
    for (size_t i = 0; i < streams_.size(); ++i) {
      if (streams_[i] != &cin)
        delete streams_[i];
    }
    if (entry_)
      delete entry_;
  }

  static STListReader<T, R> *Open(const string &filename) {
    vector<string> filenames;
    filenames.push_back(filename);
    return new STListReader<T, R>(filenames);
  }

  static STListReader<T, R> *Open(const vector<string> &filenames) {
    return new STListReader<T, R>(filenames);
  }

  void Reset() {
    FSTERROR()
        << "STListReader::Reset: stlist does not support reset operation";
    error_ = true;
  }

  bool Find(const string &key) {
    FSTERROR()
        << "STListReader::Find: stlist does not support find operation";
    error_ = true;
    return false;
  }

  bool Done() const {
    return error_ || heap_.empty();
  }

  void Next() {
    if (error_) return;
    size_t current = heap_.top().second;
    string key;
    heap_.pop();
    ReadType(*(streams_[current]), &key);
    if (!*streams_[current]) {
      FSTERROR() << "STListReader: error reading file: "
                 << sources_[current];
      error_ = true;
      return;
    }
    if (!key.empty())
      heap_.push(make_pair(key, current));

    if(!heap_.empty()) {
      current = heap_.top().second;
      if (entry_)
        delete entry_;
      entry_ = entry_reader_(*streams_[current]);
      if (!entry_ || !*streams_[current]) {
        FSTERROR() << "STListReader: error reading entry for key: "
                   << heap_.top().first << ", file: " << sources_[current];
        error_ = true;
      }
    }
  }

  const string &GetKey() const {
    return heap_.top().first;
  }

  const EntryType &GetEntry() const {
    return *entry_;
  }

  bool Error() const { return error_; }

 private:
  EntryReader entry_reader_;   // Read functor for 'EntryType'
  vector<istream*> streams_;   // Input streams
  vector<string> sources_;     // and corresponding file names
  priority_queue<
    pair<string, size_t>, vector<pair<string, size_t> >,
    greater<pair<string, size_t> > > heap_;  // (Key, stream id) heap
  mutable EntryType *entry_;   // Pointer to the currently read entry
  bool error_;

  DISALLOW_COPY_AND_ASSIGN(STListReader);
};


// String-type list header reading function template on the entry header
// type 'H' having a member function:
//   Read(istream &strm, const string &filename);
// Checks that 'filename' is an STList and call the H::Read() on the last
// entry in the STList.
// Does not support reading from stdin.
template <class H>
bool ReadSTListHeader(const string &filename, H *header) {
  if (filename.empty()) {
    LOG(ERROR) << "ReadSTListHeader: reading header not supported on stdin";
    return false;
  }
  ifstream strm(filename.c_str(), ifstream::in | ifstream::binary);
  int32 magic_number = 0, file_version = 0;
  ReadType(strm, &magic_number);
  ReadType(strm, &file_version);
  if (magic_number != kSTListMagicNumber) {
    LOG(ERROR) << "ReadSTListHeader: wrong file type: " << filename;
    return false;
  }
  if (file_version != kSTListFileVersion) {
    LOG(ERROR) << "ReadSTListHeader: wrong file version: " << filename;
    return false;
  }
  string key;
  ReadType(strm, &key);
  header->Read(strm, filename + ":" + key);
  if (!strm) {
    LOG(ERROR) << "ReadSTListHeader: error reading file: " << filename;
    return false;
  }
  return true;
}

bool IsSTList(const string &filename);

}  // namespace fst

#endif  // FST_EXTENSIONS_FAR_STLIST_H_
