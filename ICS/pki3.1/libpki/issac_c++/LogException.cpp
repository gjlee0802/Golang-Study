/**
 * @file    LogException.hpp
 * 
 * @desc    Log를 남겨야 하는 exception들
 * @author  박지영(jypark@pentasecurity.com)
 * @since   2002.05.21
 *
 * Revision history
 *
 * @date    2002.05.21 : Start
 */

// standard headers
#include <stdarg.h>
#include <sstream>

#include "LogException.hpp"
#include "LogProfile.hpp"
#include "Log.hpp"

using namespace Issac;
using namespace std;

LogException::LogException(int code)
  : Exception(LogProfile::get()->getLog()->getItem(code).desc, code)
{
}

std::string LogException::getOpts() const
{
  return _opts;
}

void LogException::addOpts(const std::string &fmt, ...)
{
  va_list args;
  va_start(args, fmt.c_str());

  if (!_opts.empty())
    _opts += ", ";
  _opts += Log::format(fmt, args);

  va_end(args);
}

