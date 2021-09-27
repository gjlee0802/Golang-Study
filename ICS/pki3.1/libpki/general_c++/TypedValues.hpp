/**
 * @file     TypedValues.hpp
 *
 * @desc     TypedValues의 기본 기능을 정의하는 클래스
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */

#ifndef ISSAC_TYPED_VALUES_HPP
#define ISSAC_TYPED_VALUES_HPP

#ifdef WIN32
  #pragma warning(disable:4786) /* prevent stl log simbol warning */
#endif

#include <string>

#include "LabeledValues.hpp"

namespace Issac
{

class TypedValues : public LabeledValues
{
public:
  virtual ~TypedValues();
  std::string getBuffer();
  void setType(std::string type);
  void loadFromBuffer(std::string buf);

  // you must overide this
  virtual std::string getType() const;
};

}

#endif
