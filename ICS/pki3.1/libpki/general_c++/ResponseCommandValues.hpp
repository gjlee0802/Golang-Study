/**
 * @file     ResponseCommandValues.hpp
 *
 * @desc     ResponseCommandValues의 기본 기능을 정의하는 클래스
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */

#ifndef ISSAC_RESPONSE_COMMAND_VALUES_HPP_
#define ISSAC_RESPONSE_COMMAND_VALUES_HPP_

#ifdef WIN32
  #pragma warning(disable:4786) /* prevent stl log simbol warning */
#endif

#include <string>
#include <vector>

#include "TypedValues.hpp"
#include "BasicCommand.hpp"

namespace Issac
{

class ResponseCommandValues : public TypedValues
{
public:
  ResponseCommandValues(const TypedValues &vals);
  ResponseCommandValues();
  virtual ~ResponseCommandValues();

  void setBasicOutputs(const std::vector<BasicOutput> &outputs);
  std::vector<BasicOutput> getBasicOutputs() const;
};

}

#endif
