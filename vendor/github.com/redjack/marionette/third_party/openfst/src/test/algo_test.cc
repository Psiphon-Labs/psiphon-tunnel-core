// algo_test.h

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
// Regression test for various FST algorithms.

#include "./algo_test.h"

// These determine which semirings are tested. Defining at least
// TEST_TROPICAL and TEST_LOG is recommended. More increase the
// comprehensiveness, but also increase the compilation time.

#define TEST_TROPICAL
#define TEST_LOG
// #define TEST_MINMAX
// #define TEST_LEFT_STRING
// #define TEST_RIGHT_STRING
// #define TEST_GALLIC
// #define TEST_LEXICOGRAPHIC
// #define TEST_POWER

DEFINE_int32(seed, -1, "random seed");
DEFINE_int32(repeat, 25, "number of test repetitions");

using fst::StdArc;
using fst::TropicalWeightGenerator;

using fst::LogArc;
using fst::LogWeightGenerator;

using fst::MinMaxArc;
using fst::MinMaxWeightGenerator;

using fst::StringArc;
using fst::StringWeightGenerator;
using fst::STRING_LEFT;
using fst::STRING_RIGHT;

using fst::GallicArc;
using fst::GallicWeightGenerator;

using fst::LexicographicArc;
using fst::TropicalWeight;
using fst::LexicographicWeightGenerator;

using fst::ArcTpl;
using fst::PowerWeight;
using fst::PowerWeightGenerator;

using fst::AlgoTester;

int main(int argc, char **argv) {
  FLAGS_fst_verify_properties = true;
  std::set_new_handler(FailedNewHandler);
  SET_FLAGS(argv[0], &argc, &argv, true);

  static const int kCacheGcLimit = 20;

  int seed = FLAGS_seed >= 0 ? FLAGS_seed : time(0);
  srand(seed);
  LOG(INFO) << "Seed = " << seed;

  FLAGS_fst_default_cache_gc = rand() % 2;
  FLAGS_fst_default_cache_gc_limit = rand() % kCacheGcLimit;
  VLOG(1) << "default_cache_gc:" << FLAGS_fst_default_cache_gc;
  VLOG(1) << "default_cache_gc_limit:" << FLAGS_fst_default_cache_gc_limit;

#ifdef TEST_TROPICAL
  TropicalWeightGenerator tropical_generator(seed, false);
  AlgoTester<StdArc, TropicalWeightGenerator>
    tropical_tester(tropical_generator, seed);
  tropical_tester.Test();
#endif  // TEST_TROPICAL

#ifdef TEST_LOG
  LogWeightGenerator log_generator(seed, false);
  AlgoTester<LogArc, LogWeightGenerator>
    log_tester(log_generator, seed);
  log_tester.Test();
#endif  // TEST_LOG

#ifdef TEST_MINMAX
  MinMaxWeightGenerator minmax_generator(seed, false);
  AlgoTester<MinMaxArc, MinMaxWeightGenerator>
      minmax_tester(minmax_generator, seed);
  minmax_tester.Test();
#endif

#ifdef TEST_LEFT_STRING
  StringWeightGenerator<int> left_string_generator(seed, false);
  AlgoTester<StringArc<>, StringWeightGenerator<int> >
    left_string_tester(left_string_generator, seed);
  left_string_tester.Test();
#endif  // TEST_LEFT_STRING

#ifdef TEST_RIGHT_STRING
  StringWeightGenerator<int, STRING_RIGHT> right_string_generator(seed, false);
  AlgoTester<StringArc<STRING_RIGHT>,
    StringWeightGenerator<int, STRING_RIGHT> >
    right_string_tester(right_string_generator, seed);
  right_string_tester.Test();
#endif  // TEST_RIGHT_STRING

#ifdef TEST_GALLIC
  typedef GallicArc<StdArc> StdGallicArc;
  typedef GallicWeightGenerator<int, TropicalWeightGenerator>
    TropicalGallicWeightGenerator;

  TropicalGallicWeightGenerator tropical_gallic_generator(seed, false);
  AlgoTester<StdGallicArc, TropicalGallicWeightGenerator>
    gallic_tester(tropical_gallic_generator, seed);
  gallic_tester.Test();
#endif  // TEST_GALLIC

#ifdef TEST_LEXICOGRAPHIC
  typedef LexicographicArc<TropicalWeight, TropicalWeight>
      TropicalLexicographicArc;
  typedef LexicographicWeightGenerator<TropicalWeightGenerator,
      TropicalWeightGenerator> TropicalLexicographicWeightGenerator;
  TropicalLexicographicWeightGenerator lexicographic_generator(seed, false);
  AlgoTester<TropicalLexicographicArc, TropicalLexicographicWeightGenerator>
      lexicographic_tester(lexicographic_generator, seed);
  lexicographic_tester.Test();
#endif  // TEST_LEXICOGRAPHIC

#ifdef TEST_POWER
  typedef PowerWeight<TropicalWeight, 3> TropicalCubeWeight;
  typedef ArcTpl<TropicalCubeWeight> TropicalCubeArc;
  typedef PowerWeightGenerator<TropicalWeightGenerator, 3>
    TropicalCubeWeightGenerator;

  TropicalCubeWeightGenerator tropical_cube_generator(seed, false);
  AlgoTester<TropicalCubeArc, TropicalCubeWeightGenerator>
    tropical_cube_tester(tropical_cube_generator, seed);
  tropical_cube_tester.Test();
#endif  // TEST_POWER

  cout << "PASS" << endl;

  return 0;
}
