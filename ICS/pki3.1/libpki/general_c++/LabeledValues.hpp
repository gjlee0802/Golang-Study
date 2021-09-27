/**
 * @file     LabeledValues.hpp
 *
 * @desc     LabeledValues의 기본 기능을 정의하는 클래스
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */

#ifndef ISSAC_LABELED_VALUES_HPP_
#define ISSAC_LABELED_VALUES_HPP_

#ifdef WIN32
  #pragma warning(disable:4786) /* prevent stl log simbol warning */
#endif

#include <string>
#include <map>

namespace Issac
{

typedef std::map<std::string, std::string> string2string;

class LabeledValues : public string2string
{
public:
  virtual std::string getBuffer();
  virtual void loadFromBuffer(std::string buf);
  virtual ~LabeledValues();
};

}

#endif
