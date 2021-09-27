#include <algorithm>

#include "base_define.h"

#include "StringHelper.hpp"

namespace Issac
{

using namespace std;

void str2strs(const std::string &str, std::vector<string> &strs, 
    const std::string &del, bool nullskip)
{
  int delsize = del.size();
  string::size_type start = 0, found;
  strs.clear();
  while ((found = str.find(del, start)) != string::npos)
  {
    if (!nullskip || found - start)
      strs.push_back(str.substr(start, found - start));
    start = found + delsize;
  }
  if (str.size() - start)
    strs.push_back(str.substr(start, str.size() - start));
}

std::string strs2str(const std::vector<string> &strs, const std::string &del,
    bool nullskip)
{
  string str;
  for (vector<string>::const_iterator i = strs.begin(); 
      i != strs.end(); ++i)
  {
    if (!nullskip || i->size())
    {
      str += *i;
      str += del;
    }
  }
  return str.substr(0, max((int)(0), (signed)(str.size()) - (signed)del.size())); 
  // 마지막 딜리미터 제거
}

}
 // end of namespace

