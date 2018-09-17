// Copyright 2009 The RE2 Authors.  All Rights Reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Simplified version of Google's logging.

#ifndef RE2_UTIL_LOGGING_H__
#define RE2_UTIL_LOGGING_H__

#include <unistd.h>  /* for write */
#include <sstream>

// Debug-only checking.
#ifndef DCHECK
#define DCHECK(condition) assert(condition)
#endif

#ifndef DCHECK_EQ
#define DCHECK_EQ(val1, val2) assert((val1) == (val2))
#endif

#ifndef DCHECK_NE
#define DCHECK_NE(val1, val2) assert((val1) != (val2))
#endif

#ifndef DCHECK_LE
#define DCHECK_LE(val1, val2) assert((val1) <= (val2))
#endif

#ifndef DCHECK_LT
#define DCHECK_LT(val1, val2) assert((val1) < (val2))
#endif

#ifndef DCHECK_GE
#define DCHECK_GE(val1, val2) assert((val1) >= (val2))
#endif

#ifndef DCHECK_GT
#define DCHECK_GT(val1, val2) assert((val1) > (val2))
#endif


// Always-on checking
#ifndef CHECK
#define CHECK(x)	if(x){}else RE2RE2RE2RE2LogMessageFatal(__FILE__, __LINE__).stream() << "Check failed: " #x
#endif

#ifndef CHECK_LT
#define CHECK_LT(x, y)	CHECK((x) < (y))
#endif

#ifndef CHECK_GT
#define CHECK_GT(x, y)	CHECK((x) > (y))
#endif

#ifndef CHECK_LE
#define CHECK_LE(x, y)	CHECK((x) <= (y))
#endif

#ifndef CHECK_GE
#define CHECK_GE(x, y)	CHECK((x) >= (y))
#endif

#ifndef CHECK_EQ
#define CHECK_EQ(x, y)	CHECK((x) == (y))
#endif

#ifndef CHECK_NE
#define CHECK_NE(x, y)	CHECK((x) != (y))
#endif


#ifndef LOG_INFO
#define LOG_INFO RE2RE2RE2RE2LogMessage(__FILE__, __LINE__)
#endif

#ifndef LOG_ERROR
#define LOG_ERROR LOG_INFO
#endif

#ifndef LOG_WARNING
#define LOG_WARNING LOG_INFO
#endif

#ifndef LOG_FATAL
#define LOG_FATAL RE2RE2RE2RE2LogMessageFatal(__FILE__, __LINE__)
#endif

#ifndef LOG_QFATAL
#define LOG_QFATAL LOG_FATAL
#endif


#ifndef VLOG
#define VLOG(x) if((x)>0){}else LOG_INFO.stream()
#endif

#ifdef NDEBUG
#define DEBUG_MODE 0
#define LOG_DFATAL LOG_ERROR
#else
#define DEBUG_MODE 1
#define LOG_DFATAL LOG_FATAL
#endif

#ifndef LOG
#define LOG(severity) LOG_ ## severity.stream()
#endif

class RE2RE2RE2RE2LogMessage {
 public:
  RE2RE2RE2RE2LogMessage(const char* file, int line) : flushed_(false) {
    stream() << file << ":" << line << ": ";
  }
  void Flush() {
    stream() << "\n";
    string s = str_.str();
    int n = (int)s.size(); // shut up msvc
    if(write(2, s.data(), n) < 0) {}  // shut up gcc
    flushed_ = true;
  }
  ~RE2RE2RE2RE2LogMessage() {
    if (!flushed_) {
      Flush();
    }
  }
  ostream& stream() { return str_; }
 
 private:
  bool flushed_;
  std::ostringstream str_;
  DISALLOW_EVIL_CONSTRUCTORS(RE2RE2RE2RE2LogMessage);
};

class RE2RE2RE2RE2LogMessageFatal : public RE2RE2RE2RE2LogMessage {
 public:
  RE2RE2RE2RE2LogMessageFatal(const char* file, int line)
    : RE2RE2RE2RE2LogMessage(file, line) { }
  ~RE2RE2RE2RE2LogMessageFatal() {
    Flush();
    abort();
  }
 private:
  DISALLOW_EVIL_CONSTRUCTORS(RE2RE2RE2RE2LogMessageFatal);
};

#endif  // RE2_UTIL_LOGGING_H__
