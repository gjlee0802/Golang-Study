/**
 * @file     LogDaemon.cpp
 *
 * @desc     LogDaemon�� �⺻ ����� �����ϴ� Ŭ����
 * @author   ������(hrcho@pentasecurity.com)
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

// conf file ����
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
  // LOG_CFG�� �꿡 ���� �ִ´�.
  _insertLOG_CFG();
  TRACE_LOG(TMPLOG, "_insertLOG_CFG");

  // ���� �α׸� ã�� DB�� �ִ´�.
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

  // [LOGD] ������ DB ������ ������ [PKIDB]�� �����Ѵ�.
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
  // Conf file�� ���������� ��´�.
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
  // log process ���� �� �Ľ��Ѵ�.
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
    // ��¥�� ������ ä �����̸��� �����Ѵ�.
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
        // ������ log_cfg ���̺� �ش� �����Ͱ� ������ ���� �߰��� �ش�.
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

      // ���� ������ ����� �д´�.
      ios::pos_type newpos = _getFileEndPos(file);
      // ��� �ִ� ������ ó���� ����� �д´�.
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

  /** ������ ó���� �Ŀ� ��¥ ���� ���θ� �Ǵ��Ѵ�. **/
  time_t now;
  time(&now);
  struct tm tmval = *localtime(&now);
  string date = type2string<struct tm>(tmval, YEAR_DAY_FORMAT);

  for (std::vector<LOG_FILE_INFO>::iterator i = _infos.begin(); 
      i != _infos.end(); ++i)
  {
    /* ��¥�� �߰��� �ٲ�� �����̸��� �ٲ��. */
    if (i->date != date)
    {
      /**
        ���� �̸��� �ٲ��� ���� �� ����¥ ������ ���
        ó���Ͽ����� �Ǵ��� �ʿ��ϴ�
        �̴� �����ϴ� �ð��� �Ϸ簡 ������ �̷���� �� �ֱ� �����̴�
       **/
      ios::pos_type newpos = _getFileEndPos(i->fileName + "." + i->date);
      if (newpos != i->pos)
        _processFile(*i);

      i->date = date;
      i->pos = 0;
    }
    else
      break; // �ϳ��� �ȹٲ�� �������� ���� �ʿ� ����.
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
    // SQL�� Ư�������� '�� ����
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
  ++i; // �̰� ���Ͽ� ������ �ʿ��� �ǳ� �ڴ�.
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

