// CALoginProfile.hpp: interface for the AuthorityLoginProfile class.
//
//////////////////////////////////////////////////////////////////////

#ifndef ISSAC_CA_LOGIN_PROFILE_HPP
#define ISSAC_CA_LOGIN_PROFILE_HPP

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifdef WIN32
#pragma warning(disable:4786)
#endif

// from libpki
#include "AuthorityLoginProfile.hpp"

namespace Issac
{

class CALoginProfile : public AuthorityLoginProfile
{
public:
  static CALoginProfile *get();
  virtual std::string getMyName() const;
  virtual CertSharedPtrs getCACerts();
  virtual void init(int argc, char * const *argv, std::string confFile,
      std::string section, std::string logDir,
      std::string logName, const LOG_TABLE_ITEMS items = NULL);

protected:
  CALoginProfile();
  virtual ~CALoginProfile();

  static void _create();
  virtual void _setDBCA();
};

}

#endif

