// far.h

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
// Finite-State Transducer (FST) archive classes.
//

#ifndef FST_EXTENSIONS_FAR_FAR_H__
#define FST_EXTENSIONS_FAR_FAR_H__

#include <fst/extensions/far/stlist.h>
#include <fst/extensions/far/sttable.h>
#include <fst/fst.h>
#include <fst/vector-fst.h>

namespace fst {

enum FarEntryType { FET_LINE, FET_FILE };
enum FarTokenType { FTT_SYMBOL, FTT_BYTE, FTT_UTF8 };

inline bool IsFst(const string &filename) {
  ifstream strm(filename.c_str());
  if (!strm)
    return false;
  return IsFstHeader(strm, filename);
}

// FST archive header class
class FarHeader {
 public:
  const string &FarType() const { return fartype_; }
  const string &ArcType() const { return arctype_; }

  bool Read(const string &filename) {
    FstHeader fsthdr;
    if (filename.empty()) {
      // Header reading unsupported on stdin. Assumes STList and StdArc.
      fartype_ = "stlist";
      arctype_ = "standard";
      return true;
    } else if (IsSTTable(filename)) {  // Check if STTable
      ReadSTTableHeader(filename, &fsthdr);
      fartype_ = "sttable";
      arctype_ = fsthdr.ArcType().empty() ? "unknown" : fsthdr.ArcType();
      return true;
    } else if (IsSTList(filename)) {  // Check if STList
      ReadSTListHeader(filename, &fsthdr);
      fartype_ = "stlist";
      arctype_ = fsthdr.ArcType().empty() ? "unknown" : fsthdr.ArcType();
      return true;
    } else if (IsFst(filename)) {  // Check if Fst
      ifstream istrm(filename.c_str());
      fsthdr.Read(istrm, filename);
      fartype_ = "fst";
      arctype_ = fsthdr.ArcType().empty() ? "unknown" : fsthdr.ArcType();
      return true;
    }
    return false;
  }

 private:
  string fartype_;
  string arctype_;
};

enum FarType {
  FAR_DEFAULT = 0,
  FAR_STTABLE = 1,
  FAR_STLIST = 2,
  FAR_FST = 3,
};

// This class creates an archive of FSTs.
template <class A>
class FarWriter {
 public:
  typedef A Arc;

  // Creates a new (empty) FST archive; returns NULL on error.
  static FarWriter *Create(const string &filename, FarType type = FAR_DEFAULT);

  // Adds an FST to the end of an archive. Keys must be non-empty and
  // in lexicographic order. FSTs must have a suitable write method.
  virtual void Add(const string &key, const Fst<A> &fst) = 0;

  virtual FarType Type() const = 0;

  virtual bool Error() const = 0;

  virtual ~FarWriter() {}

 protected:
  FarWriter() {}

 private:
  DISALLOW_COPY_AND_ASSIGN(FarWriter);
};


// This class iterates through an existing archive of FSTs.
template <class A>
class FarReader {
 public:
 typedef A Arc;

  // Opens an existing FST archive in a single file; returns NULL on error.
  // Sets current position to the beginning of the achive.
  static FarReader *Open(const string &filename);

  // Opens an existing FST archive in multiple files; returns NULL on error.
  // Sets current position to the beginning of the achive.
  static FarReader *Open(const vector<string> &filenames);

  // Resets current posision to beginning of archive.
  virtual void Reset() = 0;

  // Sets current position to first entry >= key.  Returns true if a match.
  virtual bool Find(const string &key) = 0;

  // Current position at end of archive?
  virtual bool Done() const = 0;

  // Move current position to next FST.
  virtual void Next() = 0;

  // Returns key at the current position. This reference is invalidated if
  // the current position in the archive is changed.
  virtual const string &GetKey() const = 0;

  // Returns FST at the current position. This reference is invalidated if
  // the current position in the archive is changed.
  virtual const Fst<A> &GetFst() const = 0;

  virtual FarType Type() const = 0;

  virtual bool Error() const = 0;

  virtual ~FarReader() {}

 protected:
  FarReader() {}

 private:
  DISALLOW_COPY_AND_ASSIGN(FarReader);
};


template <class A>
class FstWriter {
 public:
  void operator()(ostream &strm, const Fst<A> &fst) const {
    fst.Write(strm, FstWriteOptions());
  }
};


template <class A>
class STTableFarWriter : public FarWriter<A> {
 public:
  typedef A Arc;

  static STTableFarWriter *Create(const string &filename) {
    STTableWriter<Fst<A>, FstWriter<A> > *writer =
        STTableWriter<Fst<A>, FstWriter<A> >::Create(filename);
    return new STTableFarWriter(writer);
  }

  void Add(const string &key, const Fst<A> &fst) { writer_->Add(key, fst); }

  FarType Type() const { return FAR_STTABLE; }

  bool Error() const { return writer_->Error(); }

  ~STTableFarWriter() { delete writer_; }

 private:
  explicit STTableFarWriter(STTableWriter<Fst<A>, FstWriter<A> > *writer)
      : writer_(writer) {}

 private:
  STTableWriter<Fst<A>, FstWriter<A> > *writer_;

  DISALLOW_COPY_AND_ASSIGN(STTableFarWriter);
};


template <class A>
class STListFarWriter : public FarWriter<A> {
 public:
  typedef A Arc;

  static STListFarWriter *Create(const string &filename) {
    STListWriter<Fst<A>, FstWriter<A> > *writer =
        STListWriter<Fst<A>, FstWriter<A> >::Create(filename);
    return new STListFarWriter(writer);
  }

  void Add(const string &key, const Fst<A> &fst) { writer_->Add(key, fst); }

  FarType Type() const { return FAR_STLIST; }

  bool Error() const { return writer_->Error(); }

  ~STListFarWriter() { delete writer_; }

 private:
  explicit STListFarWriter(STListWriter<Fst<A>, FstWriter<A> > *writer)
      : writer_(writer) {}

 private:
  STListWriter<Fst<A>, FstWriter<A> > *writer_;

  DISALLOW_COPY_AND_ASSIGN(STListFarWriter);
};


template <class A>
class FstFarWriter : public FarWriter<A> {
 public:
  typedef A Arc;

  explicit FstFarWriter(const string &filename)
      : filename_(filename), error_(false), written_(false) {}

  static FstFarWriter *Create(const string &filename) {
    return new FstFarWriter(filename);
  }

  void Add(const string &key, const Fst<A> &fst) {
    if (written_) {
      LOG(WARNING) << "FstFarWriter::Add: only one Fst supported,"
                 << " subsequent entries discarded.";
    } else {
      error_ = !fst.Write(filename_);
      written_ = true;
    }
  }

  FarType Type() const { return FAR_FST; }

  bool Error() const { return error_; }

  ~FstFarWriter() {}

 private:
  string filename_;
  bool error_;
  bool written_;

  DISALLOW_COPY_AND_ASSIGN(FstFarWriter);
};


template <class A>
FarWriter<A> *FarWriter<A>::Create(const string &filename, FarType type) {
  switch(type) {
    case FAR_DEFAULT:
      if (filename.empty())
        return STListFarWriter<A>::Create(filename);
    case FAR_STTABLE:
      return STTableFarWriter<A>::Create(filename);
    case FAR_STLIST:
      return STListFarWriter<A>::Create(filename);
    case FAR_FST:
      return FstFarWriter<A>::Create(filename);
    default:
      LOG(ERROR) << "FarWriter::Create: unknown far type";
      return 0;
  }
}


template <class A>
class FstReader {
 public:
  Fst<A> *operator()(istream &strm) const {
    return Fst<A>::Read(strm, FstReadOptions());
  }
};


template <class A>
class STTableFarReader : public FarReader<A> {
 public:
  typedef A Arc;

  static STTableFarReader *Open(const string &filename) {
    STTableReader<Fst<A>, FstReader<A> > *reader =
        STTableReader<Fst<A>, FstReader<A> >::Open(filename);
    // TODO: error check
    return new STTableFarReader(reader);
  }

  static STTableFarReader *Open(const vector<string> &filenames) {
    STTableReader<Fst<A>, FstReader<A> > *reader =
        STTableReader<Fst<A>, FstReader<A> >::Open(filenames);
    // TODO: error check
    return new STTableFarReader(reader);
  }

  void Reset() { reader_->Reset(); }

  bool Find(const string &key) { return reader_->Find(key); }

  bool Done() const { return reader_->Done(); }

  void Next() { return reader_->Next(); }

  const string &GetKey() const { return reader_->GetKey(); }

  const Fst<A> &GetFst() const { return reader_->GetEntry(); }

  FarType Type() const { return FAR_STTABLE; }

  bool Error() const { return reader_->Error(); }

  ~STTableFarReader() { delete reader_; }

 private:
  explicit STTableFarReader(STTableReader<Fst<A>, FstReader<A> > *reader)
      : reader_(reader) {}

 private:
  STTableReader<Fst<A>, FstReader<A> > *reader_;

  DISALLOW_COPY_AND_ASSIGN(STTableFarReader);
};


template <class A>
class STListFarReader : public FarReader<A> {
 public:
  typedef A Arc;

  static STListFarReader *Open(const string &filename) {
    STListReader<Fst<A>, FstReader<A> > *reader =
        STListReader<Fst<A>, FstReader<A> >::Open(filename);
    // TODO: error check
    return new STListFarReader(reader);
  }

  static STListFarReader *Open(const vector<string> &filenames) {
    STListReader<Fst<A>, FstReader<A> > *reader =
        STListReader<Fst<A>, FstReader<A> >::Open(filenames);
    // TODO: error check
    return new STListFarReader(reader);
  }

  void Reset() { reader_->Reset(); }

  bool Find(const string &key) { return reader_->Find(key); }

  bool Done() const { return reader_->Done(); }

  void Next() { return reader_->Next(); }

  const string &GetKey() const { return reader_->GetKey(); }

  const Fst<A> &GetFst() const { return reader_->GetEntry(); }

  FarType Type() const { return FAR_STLIST; }

  bool Error() const { return reader_->Error(); }

  ~STListFarReader() { delete reader_; }

 private:
  explicit STListFarReader(STListReader<Fst<A>, FstReader<A> > *reader)
      : reader_(reader) {}

 private:
  STListReader<Fst<A>, FstReader<A> > *reader_;

  DISALLOW_COPY_AND_ASSIGN(STListFarReader);
};

template <class A>
class FstFarReader : public FarReader<A> {
 public:
  typedef A Arc;

  static FstFarReader *Open(const string &filename) {
    vector<string> filenames;
    filenames.push_back(filename);
    return new FstFarReader<A>(filenames);
  }

  static FstFarReader *Open(const vector<string> &filenames) {
    return new FstFarReader<A>(filenames);
  }

  FstFarReader(const vector<string> &filenames)
      : keys_(filenames), has_stdin_(false), pos_(0), fst_(0), error_(false) {
    sort(keys_.begin(), keys_.end());
    streams_.resize(keys_.size(), 0);
    for (size_t i = 0; i < keys_.size(); ++i) {
      if (keys_[i].empty()) {
        if (!has_stdin_) {
          streams_[i] = &cin;
          //sources_[i] = "stdin";
          has_stdin_ = true;
        } else {
          FSTERROR() << "FstFarReader::FstFarReader: stdin should only "
                     << "appear once in the input file list.";
          error_ = true;
          return;
        }
      } else {
        streams_[i] = new ifstream(
            keys_[i].c_str(), ifstream::in | ifstream::binary);
      }
    }
    if (pos_ >= keys_.size()) return;
    ReadFst();
  }

  void Reset() {
    if (has_stdin_) {
      FSTERROR() << "FstFarReader::Reset: operation not supported on stdin";
      error_ = true;
      return;
    }
    pos_ = 0;
    ReadFst();
  }

  bool Find(const string &key) {
    if (has_stdin_) {
      FSTERROR() << "FstFarReader::Find: operation not supported on stdin";
      error_ = true;
      return false;
    }
    pos_ = 0;//TODO
    ReadFst();
    return true;
  }

  bool Done() const { return error_ || pos_ >= keys_.size(); }

  void Next() {
    ++pos_;
    ReadFst();
  }

  const string &GetKey() const {
    return keys_[pos_];
  }

  const Fst<A> &GetFst() const {
    return *fst_;
  }

  FarType Type() const { return FAR_FST; }

  bool Error() const { return error_; }

  ~FstFarReader() {
    if (fst_) delete fst_;
    for (size_t i = 0; i < keys_.size(); ++i)
      delete streams_[i];
  }

 private:
  void ReadFst() {
    if (fst_) {
      delete fst_;
      fst_ = 0;
    }
    if (pos_ >= keys_.size()) return;
    streams_[pos_]->seekg(0);
    fst_ = Fst<A>::Read(*streams_[pos_], FstReadOptions());
    if (!fst_) {
      FSTERROR() << "FstFarReader: error reading Fst from: " << keys_[pos_];
      error_ = true;
    }
  }

 private:
  vector<string> keys_;
  vector<istream*> streams_;
  bool has_stdin_;
  size_t pos_;
  mutable Fst<A> *fst_;
  mutable bool error_;

  DISALLOW_COPY_AND_ASSIGN(FstFarReader);
};

template <class A>
FarReader<A> *FarReader<A>::Open(const string &filename) {
  if (filename.empty())
    return STListFarReader<A>::Open(filename);
  else if (IsSTTable(filename))
    return STTableFarReader<A>::Open(filename);
  else if (IsSTList(filename))
    return STListFarReader<A>::Open(filename);
  else if (IsFst(filename))
    return FstFarReader<A>::Open(filename);
  return 0;
}


template <class A>
FarReader<A> *FarReader<A>::Open(const vector<string> &filenames) {
  if (!filenames.empty() && filenames[0].empty())
    return STListFarReader<A>::Open(filenames);
  else if (!filenames.empty() && IsSTTable(filenames[0]))
    return STTableFarReader<A>::Open(filenames);
  else if (!filenames.empty() && IsSTList(filenames[0]))
    return STListFarReader<A>::Open(filenames);
  else if (!filenames.empty() && IsFst(filenames[0]))
    return FstFarReader<A>::Open(filenames);
  return 0;
}

}  // namespace fst

#endif  // FST_EXTENSIONS_FAR_FAR_H__
