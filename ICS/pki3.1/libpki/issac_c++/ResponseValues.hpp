/**
 * @file     ResponseValues.hpp
 *
 * @desc     ResponseValues의 기본 기능을 정의하는 클래스
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */

#ifndef ISSAC_RESPONSE_VALUES_HPP_
#define ISSAC_RESPONSE_VALUES_HPP_

#ifdef WIN32
  #pragma warning(disable:4786) /* prevent stl log simbol warning */
#endif

#include <string>
#include <vector>

#include "TypedValues.hpp"

namespace Issac
{

class ResponseValues : public TypedValues
{
public:
  ResponseValues(const TypedValues &vals);
  ResponseValues();
  virtual ~ResponseValues();

  void setResponse(const std::string &res);
  std::string getResponse() const;
  virtual std::string getType() const;
};

}

#endif
