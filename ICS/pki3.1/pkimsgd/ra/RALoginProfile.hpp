// RALoginProfile.hpp: interface for the AuthorityLoginProfile class.
//
//////////////////////////////////////////////////////////////////////

#ifndef ISSAC_RA_LOGIN_PROFILE_HPP
#define ISSAC_RA_LOGIN_PROFILE_HPP

#include <string>

#include "AuthorityLoginProfile.hpp"

namespace Issac
{

class RALoginProfile : public AuthorityLoginProfile
{
public:
  static RALoginProfile *get();
  virtual std::string getMyName() const;
  virtual void init(int argc, char * const *argv, std::string confFile,
      std::string section, std::string logDir,
      std::string logName, const LOG_TABLE_ITEMS items = NULL);

protected:
  RALoginProfile();
  virtual ~RALoginProfile();

  static void _create();
};

}

#endif
