// Profile.hpp: interface for the Profile class.
//
//////////////////////////////////////////////////////////////////////

#ifndef ISSAC_PROFILE_HPP_
#define ISSAC_PROFILE_HPP_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifdef WIN32
#pragma warning(disable:4786)
#endif

#include <string>

namespace Issac {

/**
 * @brief Profile 저장소에 대한 interface를 정의한 abstract class
 */
class Profile
{
public:
  virtual ~Profile();

  virtual const std::string get(std::string sec, std::string attr) = 0;
  virtual void set(std::string sec, std::string attr, std::string val) = 0;
};

} // end of namespace 

#endif

