#ifdef WIN32
#pragma warning(disable:4786)
#endif
#include <stdio.h>
#include <iostream>
#include <stdexcept>
#include <sstream>

#include "Trace.h"

// libauthority
#include "CALoginProfile.hpp"
//#include "CommandStrings.hpp"
#include "Log.hpp"
#include "PKILogTableDefine.hpp"

#include "DBConnection.hpp"
#include "DBSubject.hpp"
#include "ISSACLicense.hpp"
#include "license.h"

#define E_S_LOGIN_PROF_NOT_INITIALIZED     \
                              "CALoginProfile이 초기화되지 않았습니다."

namespace Issac
{

using namespace std;
using namespace Issac::DB;

#define THROW_IF_NOT_INITIALIZED _START \
  if (!_inst) { \
    TRACE(PRETTY_TRACE_STRING); \
    throw Exception(E_S_LOGIN_PROF_NOT_INITIALIZED); \
  } _END

CALoginProfile *CALoginProfile::get()
{
  if(_inst == NULL)
  {
    if (_destroyed)
    {
      _deadReference();
    }
    else
    {
      _create();
    }
  }
  return dynamic_cast<CALoginProfile *>(_inst);
}

void CALoginProfile::_create()
{
  static CALoginProfile profile;
  _inst = &profile;
}

CALoginProfile::~CALoginProfile()
{
}

CALoginProfile::CALoginProfile()
{
}

void CALoginProfile::_setDBCA()
{
  ostringstream ost;
  ost << "TYPE='" << PKIDB_AUTHORITY_TYPE_SELF << '\'';
  DBObjectBase::setCA(DBAuthority::select(ost.str().c_str()));
}

CertSharedPtrs CALoginProfile::getCACerts()
{
  static bool called = false;
  if (called)
    return _caCerts;

  called = true;
  CnKSharedPtrs::iterator i;
  for (i = _myCnKs.begin(); i != _myCnKs.end(); ++i)
    _caCerts.push_back(i->first);

  return _caCerts;
}

string CALoginProfile::getMyName() const
{
  return "CA";
}

void CALoginProfile::init(int argc, char * const *argv, string confFile,
    string section, string logDir,
    string logName, const LOG_TABLE_ITEMS items)
{
  AuthorityLoginProfile::init(argc, argv, confFile, section, logDir,
      logName, items);
  TRACE(PRETTY_TRACE_STRING);
  ISSACLicense::loadLicense(
      AuthorityLoginProfile::get()->getLicenseCertFile(),
      AuthorityLoginProfile::get()->getLicensePrikeyFile(),
      LICENSE_ISSACPKI_CA_3_0);
  TRACE(PRETTY_TRACE_STRING);

  #include "PKILogTableDefine.inc"
  getLog()->setTableItems(__pkiLogTableItems);
  TRACE(PRETTY_TRACE_STRING);
}

}
