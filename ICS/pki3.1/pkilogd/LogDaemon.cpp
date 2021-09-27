/**
 * @file     LogDaemon.cpp
 *
 * @desc     LogDaemon의 기본 기능을 정의하는 클래스
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>

#include <algorithm>

// std header
#include <string>
#include <vector>
#include <iostream>
#include <fstream>

// boost header
#include <boost/tokenizer.hpp>

// issac header
#include "dbi.h"
#include "pkidb.h"
#include "ISSACLog.h"

// from libpki
#include "Trace.h"
#include "separator.h"
#include "type_cast.hpp"
#include "LoginProfile.hpp"
#include "SocketHelper.h"

#include "DBConnection.hpp"
#include "SQLString.hpp"

#include "LogDaemon.hpp"
#include "LogDaemonSQLStringDefine.h"
#include "LoginProfileDBConnection.hpp"

#define HMAC_PASSWD                  "0123456789ABCDEF"

#define LOG_GROUP                    "PKI"
#define LOG_TYPE                     "SYSTEM"
#define LOG_TYPE_SYSTEM               10
#define LOG_TYPE_SYSTEM_STR          "10"
#define TABLE_NAME                   "PKI_SLOG"
#define LOG_VALID_TIME                1

// conf file 정보
#define PKI_SYSTEM_PROFILE_SECTION   "SYSTEM"
#define PKI_SYSTEM_PROFILE_KEY_NAME  "NAME"
// [PKI DB]
#define PKI_DB_PROFILE_SECTION       "PKIDB"
#define PKI_DB_PROFILE_KEY_IP        "IP"
#define PKI_DB_PROFILE_KEY_ID        "ID"
#define PKI_DB_PROFILE_KEY_PASSWD    "PASSWORD"
#define PKI_DB_PROFILE_KEY_NAME      "NAME"
// [LOGD]
#define PROFILE_SECTION              "LOGD"
#define PROFILE_KEY_SLEEP_PERIOD     "PERIOD"
#define PROFILE_KEY_LOG_RECOVERY     "RECOVERY"
#define PROFILE_KEY_PROCESS          "PROCESS"
#define PROFILE_KEY_DB_IP            "DB_IP"
#define PROFILE_KEY_DB_ID            "DB_ID"
#define PROFILE_KEY_DB_PASSWD        "DB_PASSWD"
#define PROFILE_KEY_DB_NAME          "DB_NAME"

#define LOG_FILE_DELIMITER_STR       "."

#define TMPLOG "/tmp/logd.log"

namespace Issac
{

using namespace std;
using namespace DB;

// from type_cast.hpp
static const string YEAR_DAY_FORMAT = string(YEAR) + MONTH + MDAY;

LogDaemon::LogDaemon()
{
  _readConf();
  _makeLogFileInfos();
}

LogDaemon::~LogDaemon()
{
  DBConnection::close();
}

void LogDaemon::afterDaemonize()
{
  // logdb conn
  _connectDB();
  TRACE_LOG(TMPLOG, "_connectDB");
  // LOG_CFG에 룰에 의해 넣는다.
  _insertLOG_CFG();
  TRACE_LOG(TMPLOG, "_insertLOG_CFG");

  // 빠진 로그를 찾아 DB에 넣는다.
  _restore();
  TRACE_LOG(TMPLOG, "_restore");

  while (true)
  {
    sleep(_period);
    _process();
    TRACE_LOG(TMPLOG, "_process");
  }
}

void LogDaemon::_connectDB()
{
  string pkidbip, pkidbid, pkidbpasswd, pkidbname;
  string logdbip, logdbid, logdbpasswd, logdbname;

  // [LOGD] 설정에 DB 설정이 없으면 [PKIDB]를 참조한다.
  pkidbip = LoginProfile::get()->getProfile(PKI_DB_PROFILE_SECTION, 
      PKI_DB_PROFILE_KEY_IP);
  pkidbid = LoginProfile::get()->getProfile(PKI_DB_PROFILE_SECTION, 
      PKI_DB_PROFILE_KEY_ID);
  pkidbpasswd = LoginProfile::get()->getProfile(PKI_DB_PROFILE_SECTION, 
      PKI_DB_PROFILE_KEY_PASSWD);
  pkidbname = LoginProfile::get()->getProfile(PKI_DB_PROFILE_SECTION, 
      PKI_DB_PROFILE_KEY_NAME);

  logdbip = LoginProfile::get()->getProfile(PROFILE_SECTION, 
      PROFILE_KEY_DB_IP);
  logdbid = LoginProfile::get()->getProfile(PROFILE_SECTION, 
      PROFILE_KEY_DB_ID);
  logdbpasswd = LoginProfile::get()->getProfile(PROFILE_SECTION, 
      PROFILE_KEY_DB_PASSWD);
  logdbname = LoginProfile::get()->getProfile(PROFILE_SECTION, 
      PROFILE_KEY_DB_NAME);

  if (((pkidbip == logdbip) && (pkidbid == logdbid) &&
        (pkidbpasswd == logdbpasswd) && (pkidbname == logdbname)) ||
      (logdbip.empty() || logdbid.empty() || logdbpasswd.empty() ||
       logdbname.empty()))
  {
    TRACE_LOG(TMPLOG, "use pkidb ip: %s, id: %s, passwd: %s, name: %s",
        pkidbip.c_str(), pkidbid.c_str(), pkidbpasswd.c_str(), pkidbname.c_str());
    LoginProfileDBConnection_Connect();
  }
  else
  {
    TRACE_LOG(TMPLOG, "LOGDB ip: %s, id: %s, passwd: %s, name: %s",
        logdbip.c_str(), logdbid.c_str(), logdbpasswd.c_str(), logdbname.c_str());
    DBConnection::connect(logdbip, logdbid, logdbpasswd, logdbname);
  }
}

// ok
void LogDaemon::_readConf()
{
  // Conf file의 설정값들을 얻는다.
  _period = atoi(LoginProfile::get()->getProfile(PROFILE_SECTION, 
        PROFILE_KEY_SLEEP_PERIOD).c_str());
  if (_period == 0)
    _period = 2;
  _system = LoginProfile::get()->getProfile(PKI_SYSTEM_PROFILE_SECTION, 
      PKI_SYSTEM_PROFILE_KEY_NAME);

  char hostname[1024]; char ip[128];
  gethostname(hostname, 1024);
  GetIPAddress(hostname, ip);
  _ip = ip;
  _recovery = atoi(LoginProfile::get()->getProfile(PROFILE_SECTION, 
        PROFILE_KEY_LOG_RECOVERY).c_str());
  if (_recovery == 0)
    _recovery = 3;
}

void LogDaemon::_makeLogFileInfos()
{
  // log process 값을 얻어서 파싱한다.
  string process = LoginProfile::get()->getProfile(PROFILE_SECTION, 
      PROFILE_KEY_PROCESS);

  boost::tokenizer< boost::escaped_list_separator<char> > tok(process);
  for (boost::tokenizer< boost::escaped_list_separator<char> >::iterator i =
      tok.begin(); i != tok.end(); ++i)
  {
    if (i->empty())
      continue;

    LOG_FILE_INFO info;
    info.name = string(LOG_TYPE) + " " + *i;
    // log name = SYSTEM CAMSGD
    info.process = *i;
    // 날짜를 제외한 채 파일이름을 포맷한다.
    info.fileName = 
      LoginProfile::get()->getLogDir() + 
      FILE_SEPARATOR +
      LOG_GROUP + 
      LOG_FILE_DELIMITER_STR +
      _system.c_str() + 
      LOG_FILE_DELIMITER_STR + 
      _ip.c_str() + 
      LOG_FILE_DELIMITER_STR + 
      i->c_str() + 
      LOG_FILE_DELIMITER_STR + 
      LOG_TYPE_SYSTEM_STR + 
      LOG_FILE_DELIMITER_STR + 
      LOG_TYPE;

    info.pos = 0;

    _infos.push_back(info);
  }
}

ios::pos_type LogDaemon::_getFileEndPos(const std::string &fileName)
{
  struct stat buf;
  buf.st_size = 0;
  stat(fileName.c_str(), &buf);
  return buf.st_size;

  /*
  ifstream file(fileName.c_str());
  if (!file)
    return 0;
  file.seekg(0, ios::end);
  return file.tellg();
  */
}

void LogDaemon::_insertLOG_CFG()
{
  SQLString sql;
  for (std::vector<LOG_FILE_INFO>::iterator i = _infos.begin(); 
      i != _infos.end(); ++i)
  {
    sql.format(LOG_DAEMON_SQL_FORMAT_SELECT_CFG_COUNT, i->fileName.c_str());
    int num = atoi(sql.selectOne(DBConnection::getConn()).c_str());
    if (num == 0)
    {
      try
      {
        // 기존에 log_cfg 테이블에 해당 데이터가 없으면 새로 추가해 준다.
        sql.format(LOG_DAEMON_SQL_FORMAT_INSERT_CFG, 
            LOG_GROUP, _system.c_str(), _ip.c_str(), 
            i->process.c_str(), LOG_TYPE_SYSTEM, 
            i->name.c_str(), LOG_TYPE, 
            i->fileName.c_str(), TABLE_NAME, 
            LOG_VALID_TIME, _recovery);
        sql.execute(DBConnection::getConn());
      }
      catch (exception &e)
      {
        TRACE_LOG(TMPLOG, e.what());
      }
    }
  }
}

void LogDaemon::_restore()
{
  time_t now;
  time(&now);

  for (vector<LOG_FILE_INFO>::iterator i = _infos.begin();
      i != _infos.end(); ++i)
  {
    for (int j = _recovery; j >= 0 ; --j)
    {
      struct tm tmval;
      time_t t = now - 3600*24*j;
      tmval = *localtime(&t);
      i->date = type2string<struct tm>(tmval, YEAR_DAY_FORMAT);  
	    string file = i->fileName + "." + i->date;

      if (access(file.c_str(), R_OK) != 0)
        continue;

      if (ISSACLog_CheckHMAC(i->fileName.c_str(), i->date.c_str(), HMAC_PASSWD) < 0) 
      {
        TRACE_LOG(TMPLOG, "HMAC error: %s", file.c_str());
        // FIXME need log
        continue;
      }

      // 현재 파일을 사이즈를 읽는다.
      ios::pos_type newpos = _getFileEndPos(file);
      // 디비에 있는 직전에 처리한 사이즈를 읽는다.
      i->pos = _getMaxSizeFromDB(*i);
      
      if (newpos > (i->pos))
        _processFile(*i);
    }
  }
}

void LogDaemon::_process()
{
  for (std::vector<LOG_FILE_INFO>::iterator i = _infos.begin(); 
      i != _infos.end(); ++i)
  {
    ios::pos_type newpos = _getFileEndPos(i->fileName + "." + i->date);
    if (newpos != i->pos)
    {
      _processFile(*i);
    }
  }

  /** 파일을 처리한 후에 날짜 변경 여부를 판단한다. **/
  time_t now;
  time(&now);
  struct tm tmval = *localtime(&now);
  string date = type2string<struct tm>(tmval, YEAR_DAY_FORMAT);

  for (std::vector<LOG_FILE_INFO>::iterator i = _infos.begin(); 
      i != _infos.end(); ++i)
  {
    /* 날짜가 중간에 바뀌면 파일이름도 바뀐다. */
    if (i->date != date)
    {
      /**
        파일 이름을 바꾸지 전에 이 전날짜 파일을 모두
        처리하였는지 판단이 필요하다
        이는 저장하는 시간이 하루가 지나서 이루어질 수 있기 때문이다
       **/
      ios::pos_type newpos = _getFileEndPos(i->fileName + "." + i->date);
      if (newpos != i->pos)
        _processFile(*i);

      i->date = date;
      i->pos = 0;
    }
    else
      break; // 하나가 안바뀌면 나머지도 비교할 필요 없다.
  }
}

ios::pos_type LogDaemon::_getMaxSizeFromDB(const LOG_FILE_INFO &info)
{
  SQLString sql;
  sql.format(LOG_DAEMON_SQL_FORMAT_SELECT_MAX_SIZE,  
      TABLE_NAME, _system.c_str(),
      info.process.c_str(), _ip.c_str(),
      info.name.c_str(), info.date.c_str(), YEAR_DAY_FORMAT.c_str(),
      info.date.c_str(), YEAR_DAY_FORMAT.c_str());

  return atoi(sql.selectOne(DBConnection::getConn()).c_str());
}

void LogDaemon::_insertLog(const LOG_FILE_INFO &info, const string &line, 
    ios::pos_type pos)
{
  string modline;
  modline.reserve(line.size() + 10);

  for (string::const_iterator i = line.begin(); i != line.end(); ++i)
  {
    // SQL의 특수문자인 '를 보정
    if (*i == '\'')
      modline += "''";
    else
      modline.push_back(*i);
  }

  typedef boost::tokenizer<boost::char_separator<char> > tokenizer;
  boost::char_separator<char> sep(";", "", boost::keep_empty_tokens);
  tokenizer tok(modline, sep);

  tokenizer::iterator i = tok.begin();
  const string group = *i;
  const string system = *(++i);
  const string ip = *(++i);
  const string process = *(++i);
  int type = atoi((++i)->c_str());

  const string name = info.name;
  ++i; // 이건 파일에 있지만 필요없어서 건너 뛴다.
  const string time = *(++i);
  const int size = pos;
  const int code = atoi((++i)->c_str());
  const string severity = *(++i);

  const string category = *(++i);
  string des = *(++i); if (des.size() > 2048) des.resize(2048);
  string opt = *(++i); if (opt.size() > 2048) opt.resize(2048);
  const string reqip = *(++i);
  const string reqdn = *(++i);

  const string reqid = *(++i);
  const string reqtype = *(++i);
  const string subjectdn = *(++i);
  const string subjectid = *(++i);

  SQLString sql;
  sql.format(LOG_DAEMON_SQL_FORMAT_INSERT_LOG, 
      group.c_str(), system.c_str(), ip.c_str(), process.c_str(), type, 
      name.c_str(), time.c_str(), size, code, severity.c_str(), 
      category.c_str(), des.c_str(), opt.c_str(), reqip.c_str(), reqdn.c_str(), 
      reqid.c_str(), reqtype.c_str(), subjectdn.c_str(), subjectid.c_str());
  sql.execute(DBConnection::getConn());
}

void LogDaemon::_processFile(LOG_FILE_INFO &info)
{
	char line[8192];

  ifstream file((info.fileName + "." + info.date).c_str());

  if (!file)
    return;

  file.seekg(info.pos, ios::beg);
  while (file.getline(line, 8192))
	{
    try
    {
      _insertLog(info, line, file.tellg());
      TRACE_LOG(TMPLOG, "=== _insertLog ok - %s", info.fileName.c_str());
    }
    catch (exception &e)
    {
      TRACE_LOG(TMPLOG, "^^^ insertLog error - %s", e.what());
      // FIXME need log
      break;
    }

	  info.pos = file.tellg();
	}
}

} // namespace Issac

