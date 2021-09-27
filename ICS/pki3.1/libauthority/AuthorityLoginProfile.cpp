#ifdef WIN32
#pragma warning(disable:4786)
#endif
#include <stdio.h>
#include <iostream>
#include <stdexcept>
#include <sstream>

// libpki
#include "LocalProfile.hpp"
#include "CommandLineArgs.h"
#include "PrivateKeyShare.h"
#include "CnKStorage.hpp"
#include "EncryptedProfileDecorator.hpp"
#include "separator.h"
#include "Trace.h"
#include "Echo.h"
#include "TypedValues.hpp"
#include "Socket.hpp"
#include "Exception.hpp"
#include "cis_cast.hpp"

// libdb
#include "DBProfile.hpp"
#include "DBConnection.hpp"
#include "DBSubject.hpp"
#include "DBPKC.hpp"
#include "LoginProfileDBConnection.hpp"

// libauthority
#include "AuthorityLoginProfile.hpp"
#include "IDPASSWDsValues.hpp"
#include "Log.hpp"
#include "AuthorityLogTableDefine.hpp"

#define MAX_LOGIN               3

#define R_ID_PASSWD_INCORRECT "입력한 아이디와 패스워드가 올바르지 않습니다."

#define E_S_LOGIN_PROF_NOT_INITIALIZED     \
                              "AuthorityLoginProfile이 초기화되지 않았습니다."
#define E_S_LOGIN_PROF_FAIL_TO_FIND_KEYID_CERT \
                              "해당 키 아이디의 인증서를 찾을 수 없습니다."
#define E_S_BAD_DB_SCHEMA                  \
                              "데이터베이스의 스키마가 올바르지 않습니다."
#define E_S_BAD_IDPASSWD_NUM                  \
                              "실행인자로 주어진 아이디와 패스워드의 수가 모자랍니다."

namespace Issac
{
using namespace std;
using namespace DB;

#define THROW_IF_NOT_INITIALIZED _START \
  if (!_inst) { \
    throw Exception(E_S_LOGIN_PROF_NOT_INITIALIZED); \
  } _END

// 아래의 싱글턴 관련 구현 중 static 멤버 함수 부분은 가상함수 지원이 되지 
// 않아서 get과 _create는 LoginProfile 코드를 그대로 복사해야 했다.

AuthorityLoginProfile *AuthorityLoginProfile::get()
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
  return dynamic_cast<AuthorityLoginProfile *>(_inst);
}

AuthorityLoginProfile::~AuthorityLoginProfile()
{
}

AuthorityLoginProfile::AuthorityLoginProfile()
{
  _dp.reset(new DB::DBProfile());
}

void AuthorityLoginProfile::_create()
{
  static AuthorityLoginProfile profile;
  _inst = &profile;
}

void AuthorityLoginProfile::init(int argc, char * const *argv, 
    std::string confFile,
    std::string section, std::string logDir, 
    std::string logName, const LOG_TABLE_ITEMS items)
{
  LoginProfile::init(argc, argv, confFile, section, logDir, 
      logName, items);

  // AuthorityLoginProfile을 위한 기본적인 테이블 아이템을 설정한다.
  #include "AuthorityLogTableDefine.inc"
  getLog()->setTableItems(__authLogTableItems);

  _nidSymmAlg = NID_seedCBC;

  _licenseCertFile     = getSysDir() + "license.cer";
  _licensePrikeyFile   = getSysDir() + "license.key";

  _authPrikeyFile      = getSysDir() + "ca.shk";
  _authCertFile        = getSysDir() + "ca.cer";
  _keyHistFile         = getSysDir() + "ca.his";
  _instCheckFile       = getLogDir() + "ca.inst";

  if (::KEYSHARE_GetReqInfosNum(&_reqAdminNum, _authPrikeyFile.c_str()))
     throw Exception("error KEYSHARE_GetReqInfosNum");
}

Nid AuthorityLoginProfile::getDefaultSymmAlgNid()
{
  THROW_IF_NOT_INITIALIZED;
  static bool called = false;

  if (called)
    return _nidSymmAlg;

  called = true;
  try
  {
    DB::DBProfile p;
    string nid = p.get(
      PKIDB_GLOBAL_POLICY_SECTION, PKIDB_GLOBAL_POLICY_DEFAULT_SYMMALG);
    _nidSymmAlg = string2type<Nid>(nid);
  }
  catch (Exception& e)
  {
    LogItemSharedPtr logItem(getLog()->createLogItem());

    logItem->setLogItem(LOG_AUTHORITY_FAIL_TO_GET_SYMMALG_N, e.what());
    logItem->write();
    throw;
  }
  return _nidSymmAlg;
}

CertSharedPtrs AuthorityLoginProfile::getCACerts()
{
  static bool called = false;
  if (called)
    return _caCerts;

  called = true;
  std::ostringstream ost;
  ost <<
    "ASID='" << CA_SUP_AUTHORITY_SID << "' AND " <<
    "STAT='" << PKIDB_PKC_STAT_GOOD << "' AND EDATE > SYSDATE " <<
    "ORDER BY CDATE DESC";

  DBObjectVector caCerts(
      DBAuthorityPKC::selectObjects(ost.str().c_str()));

  if (caCerts.empty())
    throw Exception("Fail to find CA certificate in DB");

  DBObjectVector::iterator i;
  for (i = caCerts.begin(); i != caCerts.end(); ++i)
    _caCerts.push_back(dynamic_cast<DBPKC*>(i->get())->getCertificate());

  return _caCerts;
}

CnKSharedPtrs AuthorityLoginProfile::getMyCnKs()
{
  static bool called = false;

  if (called)
    return _myCnKs;

  CnKStorage storage;
  try
  {
    _myCnKs = storage.loadCnKs(_id_passwds, getAuthCertFile(), 
      getAuthPrikeyFile(), 
      getKeyHistFile());
  }
  catch (exception &e)
  {
    LogItemSharedPtr logItem(getLog()->createLogItem());

    string what = e.what();
    if (what == ER_S_CNK_STORAGE_INVALID_KEY_STORAGE_INFO_FILE)
    {
      logItem->setLogItem(LOG_AUTHORITY_INVALID_HISTORY_FILE_N, what);
      logItem->write();
    }
    else
    {
      logItem->setLogItem(LOG_AUTHORITY_FAIL_TO_LOAD_PRIKEY_N, what);
      logItem->write();
    }
    throw;
  }

  return _myCnKs;
}

// LoginProfile과는 다른 복수개의 id, passwd를 이용한 로그인을 
// 재정의해야 한다.
void AuthorityLoginProfile::login(const std::vector< 
  std::pair<std::string, std::string> > &id_passwds)
{
  _id_passwds = id_passwds;
  LoginProfile::login(_id_passwds[0].first, _id_passwds[0].second);
  getMyCnKs(); // 여기서 id, passwd 복수개를 쓴다.

  DB::LoginProfileDBConnection_Connect();

  try
  {
    // db 관련 함수에 자신과 CA에 관련된 정의를 한다.
    getDefaultSymmAlgNid();
    _setDBSelf();
    _setDBCA();
    getCACerts();
  }
  catch (Exception &e)
  {
    LogItemSharedPtr logItem(getLog()->createLogItem());

    logItem->setLogItem(LOG_AUTHORITY_FAIL_TO_GET_CA_INFO_N, e.what());
    logItem->write();
    throw;
  }
}

void AuthorityLoginProfile::_checkDBSchema()
{
  // db table이 올바른지 검사
  struct TableNameNDesc
  {
    const char *name;
    PKIDBTypeDescriptor *desc;
  };
  TableNameNDesc tableNameNDesc[] =
  {
    { "global", &PKIGLOBAL },
    { "entity", &PKIENTITY },
    { "entitypkc", &PKIENTITYPKC },
    { "epmap", &PKIEPMAP },
    { "entityauth", &PKIENTITYAUTH },
    { "authority", &PKIAUTHORITY },
    { "authoritypkc", &PKIAUTHORITYPKC },
    { "authorityauth", &PKIAUTHORITYAUTH },
    { "policy", &PKIPOLICY },
    { NULL, NULL },
  };
  int i;
  for (i = 0; tableNameNDesc[i].desc != NULL; ++i)
  {
    cout << "Check Table " << tableNameNDesc[i].name << std::endl;
    int ret = ::PKI_DB_MatchTable(
      *tableNameNDesc[i].desc, DBConnection::getConn());
    if (ret != SUCCESS)
    {
      char colName[64];
      ::PKI_DB_GetFirstUnMatchingCol(
        *tableNameNDesc[i].desc,
        DBConnection::getConn(), NULL,
        colName, sizeof(colName));
      cerr << "Invalid entity table" << std::endl;

      LogItemSharedPtr logItem(getLog()->createLogItem());
      logItem->setLogItem(
        LOG_AUTHORITY_INVALID_DB_TABLE_N,
        "Table 명 : %s, Column 명 : %s",
        tableNameNDesc[i].name, colName);
      logItem->write();
      throw Exception(E_S_BAD_DB_SCHEMA);
    }
  }
}

void AuthorityLoginProfile::_setDBSelf()
{
  ostringstream ost;
  ost << "TYPE='" << PKIDB_AUTHORITY_TYPE_SELF << '\'';
  DBObjectBase::setSelf(DBAuthority::select(ost.str().c_str()));
}

void AuthorityLoginProfile::_setDBCA()
{
  ostringstream ost;
  ost << "TYPE='" << PKIDB_AUTHORITY_TYPE_SUP << '\'';
  DBObjectBase::setCA(DBAuthority::select(ost.str().c_str()));
}

void AuthorityLoginProfile::loginFromPrompt()
{
  int num = 0;
  bool ok = true;
  std::vector< std::pair<std::string, std::string> > id_passwds;
  while (1)
  {
    string id, passwd;

    for (int i = 0; i < getReqAdminNum(); i++)
    {
      id_passwds.clear();
      cout << "input admin #" << i + 1 << "'s id and password" << endl;
      // begin get id, passwd
      char buf[256];
      cout << "id:";
      cin.getline(buf, 256); id = buf;

      cout << "passwd:";

      ::EchoOff();

      memset(buf, 0, sizeof(buf));

      // input
      cin.getline(buf, 256); passwd = buf;

      ::EchoOn();

      write(1, "\n", 1);
      // end get id, passwd
      id_passwds.push_back(std::pair<std::string, std::string>(id, passwd));
    }

    try
    {
      login(id_passwds);
    }
    catch (exception &e)
    {
      ok = false;
      num++;
      if (num >= MAX_LOGIN)
        throw;
      else
        cout << R_ID_PASSWD_INCORRECT << "[" << e.what() << "]" << endl;
    }

    if (ok)
      break;
    ok = true;
  }
}

void AuthorityLoginProfile::loginFromArgs(int argc, char * const *argv)
{
  std::vector< std::pair<std::string, std::string> > id_passwds;
  string id, passwd;
  char val[256];

  ::GetOptionValueFromArgs(argc, argv, "id", "A", val);
  id = val;
  ::GetOptionValueFromArgs(argc, argv, "passwd", "B", val);
  passwd = val;
  if (!id.empty() && !passwd.empty())
    id_passwds.push_back(std::pair<std::string, std::string>(id, passwd));

  ::GetOptionValueFromArgs(argc, argv, "id2", "C", val);
  id = val;
  ::GetOptionValueFromArgs(argc, argv, "passwd2", "D", val);
  passwd = val;
  if (!id.empty() && !passwd.empty())
    id_passwds.push_back(std::pair<std::string, std::string>(id, passwd));

  ::GetOptionValueFromArgs(argc, argv, "id3", "E", val);
  id = val;
  ::GetOptionValueFromArgs(argc, argv, "passwd3", "F", val);
  passwd = val;
  if (!id.empty() && !passwd.empty())
    id_passwds.push_back(std::pair<std::string, std::string>(id, passwd));

  if (signed(id_passwds.size()) < getReqAdminNum())
    throw Exception(E_S_BAD_IDPASSWD_NUM);

  login(id_passwds);
}

void AuthorityLoginProfile::loginFromPipe()
{
  string buf;
  Socket in(0);
  in.recvLengthAndData(buf);
  in.detach(); // 소멸자에서 표준 입력을 닫지 않도록
  IDPASSWDsValues v;
  v.loadFromBuffer(buf);

  std::vector< std::pair<std::string, std::string> > id_passwds;
  v.getIDPASSWDs(id_passwds);
  login(id_passwds);
}

CnKSharedPtr AuthorityLoginProfile::getMyCnK(SubjectKeyIdentifier *keyid)
{
  getMyCnKs();

  if (keyid == NULL)
    return *(_myCnKs.begin());

  SubjectKeyIdentifier *keyidCert;  

  for (CnKSharedPtrs::iterator i = _myCnKs.begin(); i != _myCnKs.end(); i++)
  {
    keyidCert = Extensions_GetByType(NULL, 
        i->first->tbsCertificate->extensions,
        SubjectKeyIdentifier, NID_subjectKeyIdentifier);

    if (keyidCert != NULL && ASNOctStr_Cmp(keyidCert, keyid) == 0)
    {
      ASN_Del(keyidCert);
      return *i;
    }

    ASN_Del(keyidCert);
  }

  throw Exception(E_S_LOGIN_PROF_FAIL_TO_FIND_KEYID_CERT);
}

string AuthorityLoginProfile::getMyName() const
{
  return "Will Oldham";
}

}
