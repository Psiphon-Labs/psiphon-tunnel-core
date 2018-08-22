// weight_test.h

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
// Regression test for Fst weights.

#include <cstdlib>
#include <ctime>

#include <fst/expectation-weight.h>
#include <fst/float-weight.h>
#include <fst/random-weight.h>
#include "./weight-tester.h"

DEFINE_int32(seed, -1, "random seed");
DEFINE_int32(repeat, 100000, "number of test repetitions");

using fst::TropicalWeight;
using fst::TropicalWeightGenerator;
using fst::TropicalWeightTpl;
using fst::TropicalWeightGenerator_;

using fst::LogWeight;
using fst::LogWeightGenerator;
using fst::LogWeightTpl;
using fst::LogWeightGenerator_;

using fst::MinMaxWeight;
using fst::MinMaxWeightGenerator;
using fst::MinMaxWeightTpl;
using fst::MinMaxWeightGenerator_;

using fst::StringWeight;
using fst::StringWeightGenerator;

using fst::GallicWeight;
using fst::GallicWeightGenerator;

using fst::LexicographicWeight;
using fst::LexicographicWeightGenerator;

using fst::ProductWeight;
using fst::ProductWeightGenerator;

using fst::PowerWeight;
using fst::PowerWeightGenerator;

using fst::SignedLogWeightTpl;
using fst::SignedLogWeightGenerator_;

using fst::ExpectationWeight;

using fst::SparsePowerWeight;
using fst::SparsePowerWeightGenerator;

using fst::STRING_LEFT;
using fst::STRING_RIGHT;

using fst::WeightTester;

template <class T>
void TestTemplatedWeights(int repeat, int seed) {
  TropicalWeightGenerator_<T> tropical_generator(seed);
  WeightTester<TropicalWeightTpl<T>, TropicalWeightGenerator_<T> >
      tropical_tester(tropical_generator);
  tropical_tester.Test(repeat);

  LogWeightGenerator_<T> log_generator(seed);
  WeightTester<LogWeightTpl<T>, LogWeightGenerator_<T> >
      log_tester(log_generator);
  log_tester.Test(repeat);

  MinMaxWeightGenerator_<T> minmax_generator(seed);
  WeightTester<MinMaxWeightTpl<T>, MinMaxWeightGenerator_<T> >
      minmax_tester(minmax_generator);
  minmax_tester.Test(repeat);

  SignedLogWeightGenerator_<T> signedlog_generator(seed);
  WeightTester<SignedLogWeightTpl<T>, SignedLogWeightGenerator_<T> >
      signedlog_tester(signedlog_generator);
  signedlog_tester.Test(repeat);
}

int main(int argc, char **argv) {
  std::set_new_handler(FailedNewHandler);
  SET_FLAGS(argv[0], &argc, &argv, true);

  int seed = FLAGS_seed >= 0 ? FLAGS_seed : time(0);
  LOG(INFO) << "Seed = " << seed;

  TestTemplatedWeights<float>(FLAGS_repeat, seed);
  TestTemplatedWeights<double>(FLAGS_repeat, seed);
  FLAGS_fst_weight_parentheses = "()";
  TestTemplatedWeights<float>(FLAGS_repeat, seed);
  TestTemplatedWeights<double>(FLAGS_repeat, seed);
  FLAGS_fst_weight_parentheses = "";

  // Make sure type names for templated weights are consistent
  CHECK(TropicalWeight::Type() == "tropical");
  CHECK(TropicalWeightTpl<double>::Type() != TropicalWeightTpl<float>::Type());
  CHECK(LogWeight::Type() == "log");
  CHECK(LogWeightTpl<double>::Type() != LogWeightTpl<float>::Type());
  TropicalWeightTpl<double> w(15.0);
  TropicalWeight tw(15.0);

  StringWeightGenerator<int> left_string_generator(seed);
  WeightTester<StringWeight<int>, StringWeightGenerator<int> >
    left_string_tester(left_string_generator);
  left_string_tester.Test(FLAGS_repeat);

  StringWeightGenerator<int, STRING_RIGHT> right_string_generator(seed);
  WeightTester<StringWeight<int, STRING_RIGHT>,
    StringWeightGenerator<int, STRING_RIGHT> >
    right_string_tester(right_string_generator);
  right_string_tester.Test(FLAGS_repeat);

  typedef GallicWeight<int, TropicalWeight> TropicalGallicWeight;
  typedef GallicWeightGenerator<int, TropicalWeightGenerator>
    TropicalGallicWeightGenerator;

  TropicalGallicWeightGenerator tropical_gallic_generator(seed);
  WeightTester<TropicalGallicWeight, TropicalGallicWeightGenerator>
    tropical_gallic_tester(tropical_gallic_generator);
  tropical_gallic_tester.Test(FLAGS_repeat);

  typedef ProductWeight<TropicalWeight, TropicalWeight> TropicalProductWeight;
  typedef ProductWeightGenerator<TropicalWeightGenerator,
      TropicalWeightGenerator> TropicalProductWeightGenerator;

  TropicalProductWeightGenerator tropical_product_generator(seed);
  WeightTester<TropicalProductWeight, TropicalProductWeightGenerator>
      tropical_product_weight_tester(tropical_product_generator);
  tropical_product_weight_tester.Test(FLAGS_repeat);

  typedef PowerWeight<TropicalWeight, 3> TropicalCubeWeight;
  typedef PowerWeightGenerator<TropicalWeightGenerator, 3>
      TropicalCubeWeightGenerator;

  TropicalCubeWeightGenerator tropical_cube_generator(seed);
  WeightTester<TropicalCubeWeight, TropicalCubeWeightGenerator>
      tropical_cube_weight_tester(tropical_cube_generator);
  tropical_cube_weight_tester.Test(FLAGS_repeat);

  typedef ProductWeight<TropicalWeight, TropicalProductWeight>
      SecondNestedProductWeight;
  typedef ProductWeightGenerator<TropicalWeightGenerator,
      TropicalProductWeightGenerator> SecondNestedProductWeightGenerator;

  SecondNestedProductWeightGenerator second_nested_product_generator(seed);
  WeightTester<SecondNestedProductWeight, SecondNestedProductWeightGenerator>
      second_nested_product_weight_tester(second_nested_product_generator);
  second_nested_product_weight_tester.Test(FLAGS_repeat);

  // This only works with fst_weight_parentheses = "()"
  typedef ProductWeight<TropicalProductWeight, TropicalWeight>
      FirstNestedProductWeight;
  typedef ProductWeightGenerator<TropicalProductWeightGenerator,
      TropicalWeightGenerator> FirstNestedProductWeightGenerator;

  FirstNestedProductWeightGenerator first_nested_product_generator(seed);
  WeightTester<FirstNestedProductWeight, FirstNestedProductWeightGenerator>
      first_nested_product_weight_tester(first_nested_product_generator);

  typedef PowerWeight<FirstNestedProductWeight, 3> NestedProductCubeWeight;
  typedef PowerWeightGenerator<FirstNestedProductWeightGenerator, 3>
      NestedProductCubeWeightGenerator;

  NestedProductCubeWeightGenerator nested_product_cube_generator(seed);
  WeightTester<NestedProductCubeWeight, NestedProductCubeWeightGenerator>
      nested_product_cube_weight_tester(nested_product_cube_generator);

  typedef SparsePowerWeight<NestedProductCubeWeight,
      size_t > SparseNestedProductCubeWeight;
  typedef SparsePowerWeightGenerator<NestedProductCubeWeightGenerator,
      size_t, 3> SparseNestedProductCubeWeightGenerator;

  SparseNestedProductCubeWeightGenerator
      sparse_nested_product_cube_generator(seed);
  WeightTester<SparseNestedProductCubeWeight,
      SparseNestedProductCubeWeightGenerator>
      sparse_nested_product_cube_weight_tester(
          sparse_nested_product_cube_generator);

  typedef SparsePowerWeight<LogWeight, size_t > LogSparsePowerWeight;
  typedef SparsePowerWeightGenerator<LogWeightGenerator,
      size_t, 3> LogSparsePowerWeightGenerator;

  LogSparsePowerWeightGenerator
      log_sparse_power_weight_generator(seed);
  WeightTester<LogSparsePowerWeight,
      LogSparsePowerWeightGenerator>
      log_sparse_power_weight_tester(
          log_sparse_power_weight_generator);

  typedef ExpectationWeight<LogWeight, LogWeight>
      LogLogExpectWeight;
  typedef ProductWeightGenerator<LogWeightGenerator, LogWeightGenerator,
    LogLogExpectWeight> LogLogExpectWeightGenerator;

  LogLogExpectWeightGenerator log_log_expect_weight_generator(seed);
  WeightTester<LogLogExpectWeight, LogLogExpectWeightGenerator>
      log_log_expect_weight_tester(log_log_expect_weight_generator);

  typedef ExpectationWeight<LogWeight, LogSparsePowerWeight>
      LogLogSparseExpectWeight;
  typedef ProductWeightGenerator<
    LogWeightGenerator,
    LogSparsePowerWeightGenerator,
    LogLogSparseExpectWeight> LogLogSparseExpectWeightGenerator;

  LogLogSparseExpectWeightGenerator log_logsparse_expect_weight_generator(seed);
  WeightTester<LogLogSparseExpectWeight, LogLogSparseExpectWeightGenerator>
      log_logsparse_expect_weight_tester(log_logsparse_expect_weight_generator);

  // Test all product weight I/O with parentheses
  FLAGS_fst_weight_parentheses = "()";
  first_nested_product_weight_tester.Test(FLAGS_repeat);
  nested_product_cube_weight_tester.Test(FLAGS_repeat);
  log_sparse_power_weight_tester.Test(1);
  sparse_nested_product_cube_weight_tester.Test(1);
  tropical_product_weight_tester.Test(5);
  second_nested_product_weight_tester.Test(5);
  tropical_gallic_tester.Test(5);
  tropical_cube_weight_tester.Test(5);
  FLAGS_fst_weight_parentheses = "";
  log_sparse_power_weight_tester.Test(1);
  log_log_expect_weight_tester.Test(1, false); // disables division
  log_logsparse_expect_weight_tester.Test(1, false);

  typedef LexicographicWeight<TropicalWeight, TropicalWeight>
      TropicalLexicographicWeight;
  typedef LexicographicWeightGenerator<TropicalWeightGenerator,
      TropicalWeightGenerator> TropicalLexicographicWeightGenerator;

  TropicalLexicographicWeightGenerator tropical_lexicographic_generator(seed);
  WeightTester<TropicalLexicographicWeight,
      TropicalLexicographicWeightGenerator>
    tropical_lexicographic_tester(tropical_lexicographic_generator);
  tropical_lexicographic_tester.Test(FLAGS_repeat);

  cout << "PASS" << endl;

  return 0;
}
