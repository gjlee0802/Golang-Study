// standard headers
#include <cassert>
#include <sstream>
#include <algorithm>
#include <boost/scoped_array.hpp>
#include <boost/shared_array.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/lexical_cast.hpp>

// cis headers
#include "base64.h"
#include "x509pkc.h"
#include "charset.h"
#include "cmp_types.h"

// pkilib headers
#include "type_cast.hpp"
#include "Exception.hpp"

namespace Issac
{

using namespace std;

template<> std::string type2string(std::string const val)
{
  return val;
}

template<> std::string string2type(const std::string& val)
{
  return val;
}

template<> std::string type2string(int const val)
{
  ostringstream ost;
  ost << val;
  return ost.str();
}

template<> int string2type(const std::string& val)
{
  return boost::lexical_cast<int>(val.c_str());
}

template<> std::string type2string(char * const val)
{
  return val;
}

// struct tm
const char *const DEFAULT_TIME_FORMAT = "YYYYMMDD HH24:MI:SS";
const char *const YEAR   = "YYYY";
const char *const MONTH  = "MM";
const char *const MDAY   = "DD";
const char *const HOUR   = "HH24";
const char *const MIN    = "MI";
const char *const SECOND = "SS";

template<> struct std::tm string2type(const string &val)
{
  return string2type<struct tm>(val, DEFAULT_TIME_FORMAT);
}

template<> string type2string(struct tm const val)
{
  return type2string<tm>(val, DEFAULT_TIME_FORMAT);
}

template<> struct std::tm string2type(const string &t, const string &format)
{
  struct tm ret;
  string::size_type n;
  string val;

  memset(&ret, 0, sizeof(struct tm));

  val = t;
  string fmt = format;
  transform(fmt.begin(), fmt.end(), fmt.begin(), ::toupper);

  // 시간은 fmt string의 길이가 실제 값의 길이와 다르므로 가장 먼저 처리
  if ((n = fmt.find(HOUR, 0)) != fmt.npos) {
    ::sscanf(val.substr(n, 2).c_str(), "%2d", &ret.tm_hour);
    val.replace(n, 2, "");
    fmt.replace(n, strlen(HOUR), "");
  }

  if ((n = fmt.find(YEAR, 0)) != fmt.npos) {
    ::sscanf(val.substr(n, strlen(YEAR)).c_str(), "%4d", &ret.tm_year);
    ret.tm_year -= 1900;
  }

  if ((n = fmt.find(MONTH, 0)) != fmt.npos) {
    ::sscanf(val.substr(n, strlen(MONTH)).c_str(), "%2d", &ret.tm_mon);
    ret.tm_mon -= 1;
  }

  if ((n = fmt.find(MDAY, 0)) != fmt.npos) {
    ::sscanf(val.substr(n, strlen(MDAY)).c_str(), "%2d", &ret.tm_mday);
  }


  if ((n = fmt.find(MIN, 0)) != fmt.npos) {
    ::sscanf(val.substr(n, strlen(MIN)).c_str(), "%2d", &ret.tm_min);
  }
  if ((n = fmt.find(SECOND, 0)) != fmt.npos) {
    ::sscanf(val.substr(n, strlen(SECOND)).c_str(), "%2d", &ret.tm_sec);
  }

  return ret;
}

template<> string type2string(struct tm const t, const std::string &format)
{
  string ret;
  char buf[16];
  string::size_type n;

  ret = format;
  transform(ret.begin(), ret.end(), ret.begin(), ::toupper);
  while ((n = ret.find(YEAR, 0)) != ret.npos) {
    ::sprintf(buf, "%04d", t.tm_year + 1900);
    ret.replace(n, strlen(YEAR), buf);
  }

  while ((n = ret.find(MONTH, 0)) != ret.npos) {
    ::sprintf(buf, "%02d", t.tm_mon + 1);
    ret.replace(n, strlen(MONTH), buf);
  }

  while ((n = ret.find(MDAY, 0)) != ret.npos) {
    ::sprintf(buf, "%02d", t.tm_mday);
    ret.replace(n, strlen(MDAY), buf);
  }

  while ((n = ret.find(HOUR, 0)) != ret.npos) {
    ::sprintf(buf, "%02d", t.tm_hour);
    ret.replace(n, strlen(HOUR), buf);
  }

  while ((n = ret.find(MIN, 0)) != ret.npos) {
    ::sprintf(buf, "%02d", t.tm_min);
    ret.replace(n, strlen(MIN), buf);
  }

  while ((n = ret.find(SECOND, 0)) != ret.npos) {
    ::sprintf(buf, "%02d", t.tm_sec);
    ret.replace(n, strlen(SECOND), buf);
  }

  return ret;

}

} // end of namespace type

