/**
 * @file     RequestCommandValues.hpp
 *
 * @desc     RequestCommandValues의 기본 기능을 정의하는 클래스
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */

#ifndef ISSAC_REQUEST_COMMAND_VALUES_HPP_
#define ISSAC_REQUEST_COMMAND_VALUES_HPP_

#ifdef WIN32
  #pragma warning(disable:4786) /* prevent stl log simbol warning */
#endif

#include <string>
#include <vector>

#include "TypedValues.hpp"

namespace Issac
{

class RequestCommandValues : public TypedValues
{
public:
  RequestCommandValues(const TypedValues &vals);
  RequestCommandValues();
  virtual ~RequestCommandValues();

  void setHost(const std::string &host);
  std::string getHost() const;
  void setRequestID(const std::string &id);
  std::string getRequestID() const;
  void setInput(const std::string &args, const std::string &input);
  void getInput(std::string &args, std::string &input) const;
};

}

#endif
