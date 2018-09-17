#include <fst/fstlib.h>
#include <fst/script/fstscript.h>

#include "re2/re2.h"
#include "re2/regexp.h"
#include "re2/prog.h"

namespace regex2dfa {

static std::map< std::string, uint32_t > state_map;
static uint32_t state_counter = 0;

bool AttFstFromRegex(const std::string & regex, std::string * dfa) {
  // specify compile flags for re2
  re2::Regexp::ParseFlags re_flags;
  re_flags = re2::Regexp::MatchNL;
  re_flags = re_flags | re2::Regexp::OneLine;
  re_flags = re_flags | re2::Regexp::PerlClasses;
  re_flags = re_flags | re2::Regexp::PerlB;
  re_flags = re_flags | re2::Regexp::PerlX;
  re_flags = re_flags | re2::Regexp::Latin1;

  re2::RegexpStatus status;

  // compile regex to DFA
  re2::Regexp* re = NULL;
  re2::Prog* prog = NULL;

  try {
    RE2::Options opt;
    re2::Regexp* re = re2::Regexp::Parse( regex, re_flags, &status );
    if (re!=NULL) {
      re2::Prog* prog = re->CompileToProg( opt.max_mem() );
      if (prog!=NULL) {
        (*dfa) = prog->PrintEntireDFA( re2::Prog::kFullMatch );
      }
    }
  } catch (int e) {
    return false;
  }

  if ((*dfa)=="") {
    return false;
  }

  // cleanup
  if (prog!=NULL)
    delete prog;
  if (re!=NULL)
    re->Decref();

  return true;
}

std::vector<std::string> tokenize(const std::string & line,
                                  const char & delim) {
  std::vector<std::string> retval;

  std::istringstream iss(line);
  std::string fragment;
  while(std::getline(iss, fragment, delim)) {
    retval.push_back(fragment);
  }

  return retval;
}

bool StateExists(std::string state_label) {
  return (state_map.find(state_label) != state_map.end());
}

uint32_t AddState(std::string state_label) {
  state_map.insert(std::pair<std::string, uint32_t>(state_label, state_counter++));
  return state_counter;
}

uint32_t StateLookup(std::string state_label) {
  return state_map.at(state_label);
}

bool CreateFst(const std::string & str_dfa,
               fst::script::FstClass * input_fst) {

  fst::StdVectorFst fst;

  bool startStateIsntSet = true;
  std::string line;
  std::istringstream my_str_stream(str_dfa);
  while ( getline (my_str_stream,line) ) {
    if (line.empty()) {
      break;
    }

    std::vector<std::string> split_vec = tokenize(line, ' ');
    if (4 == split_vec.size()) {
      if(!StateExists(split_vec.at(0))) {
        fst.AddState();
        AddState(split_vec.at(0));
      }
      if(!StateExists(split_vec.at(1))) {
        fst.AddState();
        AddState(split_vec.at(1));
      }
      fst.AddArc(StateLookup(split_vec.at(0)),
                 fst::StdArc(atoi(split_vec.at(2).c_str()),
                             atoi(split_vec.at(3).c_str()),
                             0,
                             StateLookup(split_vec.at(1))));
    } else if (1 == split_vec.size()) {
      if(!StateExists(split_vec.at(0))) {
        fst.AddState();
      }
      uint32_t final_state = StateLookup(split_vec.at(0));
      fst.SetFinal(final_state, 0);
    }
  }

  fst.SetStart(0);

  *input_fst = static_cast<fst::script::FstClass>(fst);

  return true;
}

bool FormatFst(const std::string & str_dfa,
               std::string * formatted_dfa) {

  std::string & retval = (*formatted_dfa);

  std::string line;
  std::istringstream my_str_stream(str_dfa);
  while ( getline (my_str_stream,line) ) {
    if (line.empty()) {
      break;
    }

    std::vector<std::string> split_vec = tokenize(line, '\t');
    if (4 == split_vec.size()) {
      retval += split_vec.at(0);
      retval += "\t" + split_vec.at(1);
      retval += "\t" + split_vec.at(2);
      retval += "\t" + split_vec.at(2);
      retval += "\n";
    } else if (2 == split_vec.size()) {
      retval += split_vec.at(0);
      retval += "\n";
    }
  }

  return true;
}

bool AttFstMinimize(const std::string & str_dfa,
                    std::string * minimized_dfa) {

  fst::script::FstClass * fst = new fst::script::FstClass();

  CreateFst(str_dfa, fst);

  fst::script::MutableFstClass * mutable_fst
    = static_cast<fst::script::MutableFstClass*>(fst);
  fst::script::Minimize(mutable_fst);

  std::ostringstream ostrm;
  fst::script::PrintFst(*fst, ostrm, "", NULL, NULL, NULL, true, true);

  FormatFst(ostrm.str(), minimized_dfa);
  delete fst;

  return true;
}

bool Regex2Dfa(const std::string & regex,
               std::string * minimized_dfa) {
  state_counter = 0;
  state_map.clear();

  bool success = false;
  std::string dfa;
  bool compile_success = AttFstFromRegex(regex, &dfa);
  if (compile_success) {
    bool minimize_success = AttFstMinimize(dfa, minimized_dfa);
    success = true;
  }
  return success;
}

} // namespace regex2dfa

extern "C"  {
  int _regex2dfa(const char* input_regex, uint32_t input_regex_len, char **out, size_t *sz) {
    std::string input_regex_str(input_regex, input_regex_len);
    std::string dfa;

    bool success = regex2dfa::Regex2Dfa(input_regex_str, &dfa);
    if (!success) {
      return 1;
    }

    *sz = dfa.size();
    *out = (char*)malloc(*sz);
    memmove(*out, dfa.c_str(), *sz);
    return 0;
  }
}