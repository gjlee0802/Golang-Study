/**
 * @file     IDPASSWDsValues.hpp
 *
 * @desc     IDPASSWDsValues의 기본 기능을 정의하는 클래스
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */

#ifndef ISSAC_IDPASSWDS_VALUES_HPP_
#define ISSAC_IDPASSWDS_VALUES_HPP_

#ifdef WIN32
  #pragma warning(disable:4786) /* prevent stl log simbol warning */
#endif

#include <string>
#include <vector>

#include "TypedValues.hpp"

namespace Issac
{

class IDPASSWDsValues : public TypedValues
{
public:
  IDPASSWDsValues(const TypedValues &vals);
  IDPASSWDsValues();
  virtual ~IDPASSWDsValues();
  virtual std::string getType() const;

  void setIDPASSWD(std::string id, std::string passwd);
  void getIDPASSWD(std::string &id, std::string &passwd) const;
  void setIDPASSWDs(const std::vector< std::pair<std::string, std::string> > 
      &idpasswds);
  void getIDPASSWDs(std::vector< std::pair<std::string, std::string> > 
      &idpasswds) const;
};

}

#endif
