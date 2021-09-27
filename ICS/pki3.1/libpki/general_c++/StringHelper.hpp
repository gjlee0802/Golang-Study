
#ifndef ISSAC_STRING_HELPER_HPP
#define ISSAC_STRING_HELPER_HPP

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <string>
#include <vector>

namespace Issac 
{
  // 딜리미터가 스트링일 때 boost::tokenizer 대신 사용
  void str2strs(const std::string &str, std::vector<std::string> &strs, 
      const std::string &del, bool nullskip = false);
  std::string strs2str(const std::vector<std::string> &strs, 
      const std::string &del, bool nullskip = false);
}
 // end of namespace


#endif // ISSAC_STRING_HELPER_HPP

