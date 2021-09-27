// Exception.hpp: interface for the ForestException class.
//
//////////////////////////////////////////////////////////////////////

#ifndef ISSAC_EXCEPTION_HPP_
#define ISSAC_EXCEPTION_HPP_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifdef WIN32
#pragma warning(disable:4290) 
#pragma warning(disable:4786)
#endif

#include <string>
#include <stdexcept>

namespace Issac
{

class Exception : public std::runtime_error 
{
protected :
	int _code;

public:
  Exception(const std::string &s = 
    "Issac::Exception", int code = -1) : std::runtime_error(s), _code(code) {}
  int getCode() const { return _code; }
  virtual ~Exception() throw () {}
};

}

#endif
