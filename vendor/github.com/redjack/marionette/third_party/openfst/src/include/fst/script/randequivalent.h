
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

#ifndef FST_SCRIPT_RANDEQUIVALENT_H_
#define FST_SCRIPT_RANDEQUIVALENT_H_

#include <fst/script/arg-packs.h>
#include <fst/script/fst-class.h>
#include <fst/script/randgen.h>  // for RandArcSelection
#include <fst/randequivalent.h>

namespace fst {
namespace script {

// 1
typedef args::Package<const FstClass&, const FstClass&,
                      int32, float, int, int> RandEquivalentInnerArgs1;
typedef args::WithReturnValue<bool,
                              RandEquivalentInnerArgs1> RandEquivalentArgs1;

template<class Arc>
void RandEquivalent(RandEquivalentArgs1 *args) {
  const Fst<Arc> &fst1 = *(args->args.arg1.GetFst<Arc>());
  const Fst<Arc> &fst2 = *(args->args.arg2.GetFst<Arc>());

  args->retval = RandEquivalent(fst1, fst2, args->args.arg3, args->args.arg4,
                                args->args.arg5, args->args.arg6);
}

// 2
typedef args::Package<const FstClass &, const FstClass &, int32,
                      ssize_t, float,
                      const RandGenOptions<RandArcSelection> &>
  RandEquivalentInnerArgs2;

typedef args::WithReturnValue<bool,
                              RandEquivalentInnerArgs2> RandEquivalentArgs2;

template<class Arc>
void RandEquivalent(RandEquivalentArgs2 *args) {
  const Fst<Arc> &fst1 = *(args->args.arg1.GetFst<Arc>());
  const Fst<Arc> &fst2 = *(args->args.arg2.GetFst<Arc>());
  const RandGenOptions<RandArcSelection> &opts = args->args.arg6;
  int32 seed = args->args.arg3;

  if (opts.arc_selector == UNIFORM_ARC_SELECTOR) {
    UniformArcSelector<Arc> arc_selector(seed);
    RandGenOptions< UniformArcSelector<Arc> >
        ropts(arc_selector, opts.max_length, opts.npath);

    args->retval = RandEquivalent(fst1, fst2, args->args.arg4,
                                  args->args.arg5, ropts);
  } else if (opts.arc_selector == FAST_LOG_PROB_ARC_SELECTOR) {
    FastLogProbArcSelector<Arc> arc_selector(seed);
    RandGenOptions< FastLogProbArcSelector<Arc> >
        ropts(arc_selector, opts.max_length, opts.npath);

    args->retval = RandEquivalent(fst1, fst2, args->args.arg4,
                                  args->args.arg5, ropts);
  } else {
    LogProbArcSelector<Arc> arc_selector(seed);
    RandGenOptions< LogProbArcSelector<Arc> >
        ropts(arc_selector, opts.max_length, opts.npath);
    args->retval = RandEquivalent(fst1, fst2, args->args.arg4,
                                  args->args.arg5, ropts);
  }
}


// 1
bool RandEquivalent(const FstClass &fst1,
                    const FstClass &fst2,
                    int32 seed = time(0),
                    ssize_t num_paths = 1,
                    float delta = fst::kDelta,
                    int path_length = INT_MAX);

// 2
bool RandEquivalent(const FstClass &fst1,
                    const FstClass &fst2,
                    int32 seed,
                    ssize_t num_paths,
                    float delta,
                    const fst::RandGenOptions<
                      fst::script::RandArcSelection> &opts);

}  // namespace script
}  // namespace fst



#endif  // FST_SCRIPT_RANDEQUIVALENT_H_
