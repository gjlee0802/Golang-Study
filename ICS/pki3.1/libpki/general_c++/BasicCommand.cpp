/**
 * @file     BasicCommand.cpp
 *
 * @desc     BasicCommand 기본 기능을 정의하는 클래스
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */

#include <sys/types.h>
#include "BasicCommand.hpp"

namespace Issac
{

using namespace std;

std::string GetStringFromBasicOutputs(const std::vector<BasicOutput> &outputs, 
    string outputdelim, bool addfinaldelin)
{
  string ret;

  for (std::vector<BasicOutput>::const_iterator i = outputs.begin();
      i != outputs.end(); ++i)
  {
    if (i != outputs.begin()) ret += outputdelim;
    ret += i->second;
  }
  if (!ret.empty() && addfinaldelin)
    ret += outputdelim;

  return ret;
}

}
