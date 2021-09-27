/**
 * @file      LogImpl.hpp
 *
 * @desc      Log 구현 클래스 선언
 * @author    조현래(hrcho@pentasecurity.com)
 * @since     2003.05.22
 */

#ifndef ISSAC_LOG_IMPL_HPP_
#define ISSAC_LOG_IMPL_HPP_

#ifdef WIN32
#pragma warning(disable:4786)
#endif

#ifndef _STRING_INCLUDED_H_
#include <string>
#define _STRING_INCLUDED_H_
#endif

// issac headers
#include "ISSACLog.h"

#include "Trace.h"
#include "Exception.hpp"

#define PKI_LOG_TYPE_SYSTEM  10

namespace Issac
{

class Log::LogImpl
{
public :
  LogImpl(std::string logPath, std::string systemName, 
         std::string process, std::string logName, 
         std::string passwd, std::string group)
  {
    _ctx = ::ISSACLog_Init(
      (char *)group.c_str(),
      (char *)systemName.c_str(),
      (char *)process.c_str(),
      PKI_LOG_TYPE_SYSTEM,
      (char *)logPath.c_str(),
      (char *)logName.c_str(),
      (char *)passwd.c_str());

    if (!_ctx)
      throw Exception("Log directory does not exist");
  };

  ~LogImpl() { if (_ctx) ::ISSACLog_Close(_ctx); }

  void write(int code, std::string msg) 
  { 
    if (::ISSACLog_Write(_ctx, code, msg.c_str())) 
    throw Exception("fail to write log"); 
  }

protected:
  PKI_LOG_CONTEXT *_ctx;
};

}

#endif

