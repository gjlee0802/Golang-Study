#ifdef WIN32
#pragma warning(disable:4786)
#endif

#include <stdio.h>
#include <iostream>
#include <stdexcept>
#include <sstream>
#include <set>

// cis headers
#include "rand_hash.h"
#include "seed.h"
#include "base64.h"
#include "cmp.h" // define MAX_SYMMKEY_LEN

#include <boost/tokenizer.hpp>

// libpki
#include "LocalProfile.hpp"
#include "CommandLineArgs.h"
#include "EncryptedProfileDecorator.hpp"
#include "separator.h"
#include "Trace.h"
#include "Echo.h"
#include "Socket.hpp"
#include "Exception.hpp"

// libauthority
#include "LoginProfile.hpp"
#include "IDPASSWDsValues.hpp"

#define E_S_LOGIN_PROF_ALREADY_EXIST       \
                              "로그인 프로파일이 이미 존재합니다."
#define E_S_LOGIN_PROF_NOT_CREATED         \
                              "로그인 프로파일이 생성되지 않았습니다."
#define E_S_LOGIN_PROF_NOT_INITIALIZED     \
                              "로그인 프로파일이 초기화되지 않았습니다."
#define E_S_LOGIN_PROF_FAIL_TO_INITIALIZE  \
                              "로그인 프로파일을 초기화할 수 없습니다."
#define E_S_LOGIN_PROF_DEAD_REFERENCE      \
                              "소멸된 로그인 프로파일을 참조하였습니다."
#define E_S_LOGIN_PROF_FAIL_TO_GET_LOG_SYSTEM \
                              "로그 시스템을 설정파일로 부터 읽을 수 없습니다."

// Directory & File
#define _BIN_                 "bin"   FILE_SEPARATOR_STR
#define _SYS_                 "sys"   FILE_SEPARATOR_STR
#define _CONF_                "conf"  FILE_SEPARATOR_STR
#define _LOG_                 "log"   FILE_SEPARATOR_STR
#define _CRL_                 "crl"   FILE_SEPARATOR_STR
#define _EXT_                 "ext"   FILE_SEPARATOR_STR
#define _INST_                "inst"  FILE_SEPARATOR_STR

#define CONF_FILE             "configure"

// profile
#define SECT_USER_PREFIX      "USER_"
#define ATTR_USER_KEY         "SECRETKEY"
#define MAX_LOG_PIN_LEN       24

namespace Issac
{

using namespace std;

#define THROW_IF_NOT_INITIALIZED _START \
  if (!_inst) { \
    TRACE(PRETTY_TRACE_STRING); \
    throw Exception(E_S_LOGIN_PROF_NOT_INITIALIZED); \
  } _END

LoginProfile *LoginProfile::get()
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
  return dynamic_cast<LoginProfile *>(_inst);
}

void LoginProfile::_create()
{
  static LoginProfile profile;
  _inst = &profile;
}

LoginProfile::~LoginProfile()
{
}

LoginProfile::LoginProfile()
{
}

void LoginProfile::init(int argc, char * const *argv, string confFile,
    string section, string logDir, 
    string logName, const LOG_TABLE_ITEMS items)
{
  LogProfile::init(argc, argv, confFile, section, logDir, "", 
      logName, items);

  _rootDir = getMyDir();
  _rootDir += "..";
  _rootDir += FILE_SEPARATOR_STR;

  _binDir = _rootDir + _BIN_;
  _sysDir = _rootDir + _SYS_;
  _confDir = confFile.substr(0, confFile.rfind(FILE_SEPARATOR_STR)) + 
    FILE_SEPARATOR_STR;
  _crlDir = _rootDir + _CRL_;
  _extDir = _rootDir + _EXT_;
  _instDir = _rootDir + _INST_;

  _tmplFile = _rootDir + _CONF_ + "template";

  setPidDir(".." FILE_SEPARATOR_STR _SYS_);
}
 
void LoginProfile::initAndLogin(int argc, char * const *argv, string section, 
    string logName, const LOG_TABLE_ITEMS items)
{
  // init
  char path[256];
  char name[256];
  char val[256];
  char val2[256];

  if (::GetPathAndModuleNameFromArgs(argv[0], path, name) != 0)
    throw Exception(E_S_LOGIN_PROF_FAIL_TO_INITIALIZE);

  string rootDir = path;
  rootDir = rootDir + ".." + FILE_SEPARATOR_STR;

  if(::GetOptionValueFromArgs(argc, argv, "configre", "c", val) == 0)
  {
    if(::GetOptionValueFromArgs(argc, argv, "logname", "l", val2) == 0)
    {
      LocalProfile p(val);
      init(argc, argv, val, section, rootDir + _LOG_, val2, items);
    }
    else
    {
      LocalProfile p(val);
      init(argc, argv, val, section, rootDir + _LOG_, logName, items);
    }
  }
  else
  {
    if(::GetOptionValueFromArgs(argc, argv, "logname", "l", val2) == 0)
    {
      LocalProfile p(val);
      init(argc, argv, val, section, rootDir + _LOG_, val2, items);
    }
    else
    {
      LocalProfile p(rootDir + _CONF_ + CONF_FILE);
      init(argc, argv, rootDir + _CONF_ + CONF_FILE, section, 
        rootDir + _LOG_, logName, items);
    }
  }

  // login

  if (::GetOptionValueFromArgs(argc, argv, "fork-mode", "d", val) == 0)
  {
    loginFromPipe();
  }
  else if (::GetOptionValueFromArgs(argc, argv, "id", "A", val) == 0 &&
    ::GetOptionValueFromArgs(argc, argv, "passwd", "B", val) == 0)
  {
    loginFromArgs(argc, argv);
  }
  else // id_given
  {
    loginFromPrompt();
  }
}

void LoginProfile::login(const std::string &id, const std::string &passwd)
{
  // user login
  _setCurrentUser(id, passwd); // 여기서 _elp 할당

  // _elp 획득 이후에야 _readProfileTemplate이 의미가 있다.
  _readProfileTemplate();
}

/* 로그인 유저를 설정한다는 것은 패스워드(핀)로 16 bytes 키를 뽑고 
   그 키로 암호화 프로파일을 관리하고, 또한 DB에 접속해서 DB 커넥션을
   관리한다는 것을 의미한다.
*/
void LoginProfile::_setCurrentUser(const string &id, const string &passwd) 
{
  THROW_IF_NOT_INITIALIZED;

  std::string sec;

  // 사용자의 비밀키를 가져옴
  EncryptedProfileDecorator p = 
    EncryptedProfileDecorator(new LocalProfile(getConfFile()), passwd);

  sec = SECT_USER_PREFIX;
  sec += id;
  _key = p.get(sec, ATTR_USER_KEY);

  LocalProfile lp(getConfFile());
  TRACE(getConfFile().c_str());
  TRACE(string(sec+":"+ATTR_USER_KEY).c_str());
  if (lp.get(sec, ATTR_USER_KEY).empty())
    throw Exception("no such user");

  // 위의 16 bytes key로 새로운 암호화 프로파일을 설정한다.
  // 사용자에 관계없이 동일한 키라 _elp != NULL 이면 굳이 새로 
  // 할당할 필요없다.
  // 생성자가 핀을 받지만 키를 받지 않으므로 아래 처럼...
  _elp.reset(new EncryptedProfileDecorator(new LocalProfile(getConfFile())));
  ((EncryptedProfileDecorator *)(_elp.get()))->setKey(_key);

  _id = id; _passwd = passwd;
}

void LoginProfile::registerUser(const std::string &id, 
  const std::string &passwd, bool useCurrentKey) 
{
  std::string sec;
  std::string key;

  // 1. 비밀키 얻기
  if(_id.size() == 0 || !useCurrentKey)
  {
    unsigned char secretKey[MAX_SYMMKEY_LEN];
    // 처음으로 생성되는 관리자
    // 1. 임의의 비밀키를 생성
    RandHashContext ctx;

	  RANDHASH_Initialize(&ctx);
	  RANDHASH_GetRandomNum(secretKey, 16, &ctx);
    key.resize(16);
    memcpy((void *)key.c_str(), (void *)secretKey, 16);
  }
  else
  {
    // 현재 사용자의 비밀키를 가져옴
    key = _key;
  }

  // 2. 위의 16 bytes key를 pin(passwd)으로 암호화하여 저장한다.
  EncryptedProfileDecorator p = 
    EncryptedProfileDecorator(new LocalProfile(getConfFile()), passwd);

  sec = SECT_USER_PREFIX;
  sec += id;
  p.set(sec, ATTR_USER_KEY, key);
}

void LoginProfile::getIDPASSWD(std::string &id, std::string &passwd) const
{
  id = _id; passwd = _passwd;
}

void LoginProfile::loginFromArgs(int argc, char * const *argv)
{
  string id, passwd;
  char val[256];
  ::GetOptionValueFromArgs(argc, argv, "id", "A", val);
  id = val;
  ::GetOptionValueFromArgs(argc, argv, "passwd", "B", val);
  passwd = val;

  login(id, passwd);
}

void LoginProfile::loginFromPrompt()
{
  string id, passwd;

  cout << "input admin id and password" << endl;
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
  login(id, passwd);
}

// LoginProfile은 loginFromPipe를 통해서 하나의 아이디와 패스워드를 받는 것이
// 옳고, LoginProfile은 분산된 비공개키를 복구하기 위해 복수개를
// 받는 것이 옳지만 통일하기 위해, 복수개를 받은후 하나만 사용하는 코드를 썼다.
void LoginProfile::loginFromPipe()
{
  string buf;
  Socket in(0);
  in.recvLengthAndData(buf);
  in.detach(); // 소멸자에서 표준 입력을 닫지 않도록
  IDPASSWDsValues v;
  v.loadFromBuffer(buf);
  string id, passwd;
  v.getIDPASSWD(id, passwd);

  login(id, passwd);
}

void LoginProfile::_readProfileTemplate()
{
  _sec_attrs.clear();
  _sec_attrsCipher.clear();
  //_sec_attrsDB.clear();
  //_sec_attrsDBCipher.clear();

  _secs.clear();
  _mods.clear();

  LocalProfile p(getTmplFile());
  std::string sec = p.get("MAIN", "SECTION");

  // string to string_vector
  boost::tokenizer< boost::escaped_list_separator<char> > tok(sec);
  copy(tok.begin(), tok.end(), back_inserter(_secs));

  for (std::vector<std::string>::iterator i = _secs.begin(); 
      i != _secs.end(); ++i)
  {
    std::vector<std::string> attrs;
    string val;
    vector<string>::iterator j;

    val = p.get(*i, "ATTR");
    tok.assign(val);
    attrs.clear();
    copy(tok.begin(), tok.end(), back_inserter(attrs));
    for (j = attrs.begin(); j != attrs.end(); ++j)
      _sec_attrs.push_back(*i + " " + *j);

    val = p.get(*i, "CIPHER");
    tok.assign(val);
    attrs.clear();
    copy(tok.begin(), tok.end(), back_inserter(attrs));
    for (j = attrs.begin(); j != attrs.end(); ++j)
      _sec_attrsCipher.push_back(*i + " " + *j);

    /*
    val = p.get(*i, "DB");
    tok.assign(val);
    attrs.clear();
    copy(tok.begin(), tok.end(), back_inserter(attrs));
    for (j = attrs.begin(); j != attrs.end(); ++j)
    {
      _sec_attrsDB.push_back(*i + " " + *j);
    }

    val = p.get(*i, "DBCIPHER");
    tok.assign(val);
    attrs.clear();
    copy(tok.begin(), tok.end(), back_inserter(attrs));
    for (j = attrs.begin(); j != attrs.end(); ++j)
      _sec_attrsDBCipher.push_back(*i + " " + *j);
      */
  }

  sec = p.get("MAIN", "MODULE");
  tok.assign(sec);
  copy(tok.begin(), tok.end(), back_inserter(_mods));
}

vector<string> LoginProfile::getAllAttrsOfSection(string section) const
{
  LocalProfile p(getTmplFile());
  std::string val = p.get(section, "ATTR");
  vector<string> attrs;
  boost::tokenizer< boost::escaped_list_separator<char> > tok(val);
  copy(tok.begin(), tok.end(), back_inserter(attrs));

  return attrs;
}

string LoginProfile::getAllAttrsAndValuesOfSection(string section, 
    string delimeter1, string delimeter2) const
{
  const vector<string> attrs = getAllAttrsOfSection(section);
  if (attrs.empty())
    return "";

  string ret;
  vector<string>::const_iterator i;
  for (i = attrs.begin(); i != attrs.end(); ++i)
    ret += *i + delimeter1 + getProfile(section, *i) + delimeter2;

  return ret;
}

bool LoginProfile::isCommandProfile(const std::string &sec, 
  const std::string &attr) const
{
  THROW_IF_NOT_INITIALIZED;

  return find(_sec_attrs.begin(), _sec_attrs.end(), 
      sec + " " + attr) != _sec_attrs.end();
}

bool LoginProfile::isProfileCipher(const std::string &sec, 
  const std::string &attr) const
{
  THROW_IF_NOT_INITIALIZED;

  return find(_sec_attrsCipher.begin(), _sec_attrsCipher.end(), 
      sec + " " + attr) != _sec_attrsCipher.end();
}

void LoginProfile::setProfile(const string &attr, const string &val)
{
  setProfile(_section, attr, val);
}

string LoginProfile::getProfile(const string &attr) const
{
  return getProfile(_section, attr);
}

void LoginProfile::setProfile(const std::string &sec, 
  const std::string &attr, const std::string &val)
{
  if (isProfileCipher(sec, attr))
    getELP()->set(sec, attr, val);
  else
    LogProfile::setProfile(sec, attr, val);
}

std::string LoginProfile::getProfile(const std::string &sec, 
  const std::string &attr) const
{
  if (isProfileCipher(sec, attr))
    return getELP()->get(sec, attr);

  return LogProfile::getProfile(sec, attr);
}

}
