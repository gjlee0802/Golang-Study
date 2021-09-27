/**
 * @file    LogException.hpp
 * 
 * @desc    Log를 남겨야 하는 exception들
 * @author  조현래 (hrcho@pentasecurity.com)
 * @since   2002.05.21
 */

#ifndef ISSAC_LOG_EXCEPTION_HPP_
#define ISSAC_LOG_EXCEPTION_HPP_

// standard headers
#ifndef BOOST_SHARED_PTR_HPP_INCLUDED
#include <boost/shared_ptr.hpp>
#define BOOST_SHARED_PTR_HPP_INCLUDED
#endif

#include "Exception.hpp"
#include "cis_cast.hpp"

namespace Issac
{
/**
 * 로그를 남기기 위한 정보들을 추가로 받기 위한 exception class
 * 로그를 남기는 곳에서 발생하는 exception들은 이 class를 계승해야 한다.
 */
class LogException : public Exception
{
public:
  LogException(int code);
  virtual ~LogException() throw() {}

  /**
   * Log 추가 정보를 추가한다.
   */
  void addOpts(const std::string &fmt, ...);
  template<class _T> void addOpt(const std::string opt, _T val)
  {
    if (!_opts.empty())
      _opts += ", ";
    _opts += opt;
    _opts += " : ";
    _opts += type2string<_T>(val);
  }

  /**
   * Log 추가 정보 값을 얻는다.
   */
  std::string getOpts() const;

protected:
  std::string _opts;
};

}

#endif /* ISSAC_LOG_EXCEPTION_HPP_ */

