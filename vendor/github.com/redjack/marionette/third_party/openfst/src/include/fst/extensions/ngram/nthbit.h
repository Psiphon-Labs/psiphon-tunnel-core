
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
// Author: sorenj@google.com (Jeffrey Sorensen)
//         dr@google.com (Doug Rohde)

#ifndef FST_EXTENSIONS_NGRAM_NTHBIT_H_
#define FST_EXTENSIONS_NGRAM_NTHBIT_H_

#include <fst/types.h>

extern uint32 nth_bit_bit_offset[];

inline uint32 nth_bit(uint64 v, uint32 r) {
  uint32 shift = 0;
  uint32 c = __builtin_popcount(v & 0xffffffff);
  uint32 mask = -(r > c);
  r -= c & mask;
  shift += (32 & mask);

  c = __builtin_popcount((v >> shift) & 0xffff);
  mask = -(r > c);
  r -= c & mask;
  shift += (16 & mask);

  c = __builtin_popcount((v >> shift) & 0xff);
  mask = -(r > c);
  r -= c & mask;
  shift += (8 & mask);

  return shift + ((nth_bit_bit_offset[(v >> shift) & 0xff] >>
                   ((r - 1) << 2)) & 0xf);
}

#endif  // FST_EXTENSIONS_NGRAM_NTHBIT_H_
