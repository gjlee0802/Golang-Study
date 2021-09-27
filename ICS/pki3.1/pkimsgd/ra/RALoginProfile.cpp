#include "RALoginProfile.hpp"
#include "Log.hpp"
#include "PKILogTableDefine.hpp"

namespace Issac
{

using namespace std;

RALoginProfile *RALoginProfile::get()
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
  return dynamic_cast<RALoginProfile *>(_inst);
}

void RALoginProfile::_create()
{
  static RALoginProfile profile;
  _inst = &profile;
}

RALoginProfile::~RALoginProfile()
{
}

string RALoginProfile::getMyName() const
{
  return "RA";
}

RALoginProfile::RALoginProfile()
{
}

void RALoginProfile::init(int argc, char * const *argv, string confFile,
    string section, string logDir,
    string logName, const LOG_TABLE_ITEMS items)
{
  AuthorityLoginProfile::init(argc, argv, confFile, section, logDir,
      logName, items);

  #include "PKILogTableDefine.inc"
  getLog()->setTableItems(__pkiLogTableItems);

  _authPrikeyFile      = getSysDir() + "ra.shk";
  _authCertFile        = getSysDir() + "ra.cer";
  _keyHistFile         = getSysDir() + "ra.his";
  _instCheckFile       = getLogDir() + "ra.inst";
}

}
