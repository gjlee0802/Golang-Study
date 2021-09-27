#ifdef WIN32
#pragma warning(disable:4786)
#endif
#include <stdio.h>
#include <iostream>
#include <stdexcept>
#include <sstream>

// libpki
#include "LocalProfile.hpp"
#include "ProcessHandler.hpp"
#include "CommandLineArgs.h"
#include "separator.h"
#include "Trace.h"
#include "Exception.hpp"

// libauthority
#include "LogProfile.hpp"

#define E_S_LOG_PROF_ALREADY_EXIST       \
                              "로그 프로파일이 이미 존재합니다."
#define E_S_LOG_PROF_NOT_CREATED         \
                              "로그 프로파일이 생성되지 않았습니다."
#define E_S_LOG_PROF_NOT_INITIALIZED     \
                              "로그 프로파일이 초기화되지 않았습니다."
#define E_S_LOG_PROF_FAIL_TO_INITIALIZE  \
                              "로그 프로파일을 초기화할 수 없습니다."
#define E_S_LOG_PROF_DEAD_REFERENCE      \
                              "소멸된 로그 프로파일을 참조하였습니다."
#define E_S_LOG_PROF_LOG_NOT_INITED      \
                              "로그가 초기화되지 않았습니다."

#define MAX_LOG_PIN_LEN       24

namespace Issac
{

using namespace std;

LogProfile *LogProfile::_inst = NULL;
bool LogProfile::_destroyed = false;

LogProfile *LogProfile::get()
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
  return _inst;
}

void LogProfile::_create()
{
  static LogProfile profile;
  _inst = &profile;
}

LogProfile::~LogProfile()
{
  _inst = NULL;
  _destroyed = true;
}

LogProfile::LogProfile()
{
}

void LogProfile::_deadReference()
{
  throw Exception(E_S_LOG_PROF_DEAD_REFERENCE);
}

void LogProfile::init(int argc, char * const *argv, string confFile, 
    string section, string logDir, string logSystemName, string logName, 
    const LOG_TABLE_ITEMS items, string logGroup)
{
  char path[256];
  char name[256];
  if (::GetPathAndModuleNameFromArgs(argv[0], path, name) != 0)
    throw Exception(E_S_LOG_PROF_FAIL_TO_INITIALIZE);

  _logName = logName;

  _myDir = path;
  _pidDir = _myDir;
  _section = section;

  if (confFile.find(FILE_SEPARATOR) == 0)
    _confFile = confFile;
  else
    _confFile = _myDir + confFile;
  if (logDir.find(FILE_SEPARATOR) == 0)
    _logDir = logDir;
  else
    _logDir = _myDir + logDir;

  // set local profile
  _lp.reset(new LocalProfile(getConfFile()));
  // now, can use profile
  _logSystemName = logSystemName;
  if (_logSystemName.empty())
    _logSystemName = getProfile("LOG_SYSTEM");
  if (_logSystemName.empty())
    _logSystemName = getProfile("SYSTEM", "NAME");
  //SetProcessExecuteShell(getProfile("SYSTEM", "SHELL_EXEC"));
  _logGroup = logGroup;
  if (_logGroup.empty())
  {
    _logGroup = getProfile("LOG_GROUP");
    if (_logGroup.empty())
      _logGroup = getProfile("SYSTEM", "GROUP");
    if (_logGroup.empty())
      _logGroup = PKI_LOG_GROUP;
  }
  _initLog(_logSystemName, _logName, getLogDir(), items, _logGroup);
}

std::string LogProfile::getPidFileName(std::string section)
{
  std::transform(section.begin(), section.end(), section.begin(), ::tolower);
  return section + ".lock";
}

void LogProfile::setPidDir(const std::string &relDir2MyDir)
{
  _pidDir = _myDir + FILE_SEPARATOR_STR + relDir2MyDir;
}

std::string LogProfile::getPidFile(string section) const 
{ 
  if (section.empty())
    return _pidDir + FILE_SEPARATOR_STR + getPidFileName(_section);
  else
    return _pidDir + FILE_SEPARATOR_STR + getPidFileName(section);
}

Log* LogProfile::getLog() 
{ 
  if (_log.get())
    return _log.get(); 
  else
    throw Exception(E_S_LOG_PROF_LOG_NOT_INITED);
}

void LogProfile::_initLog(string logSystemName, string logName, string logDir, 
    const LOG_TABLE_ITEMS items, string logGroup)
{
  string logPin = getProfile("LOG_HMAC_KEY");
  if (logPin.empty())
    logPin = getProfile("SYSTEM", "HMAC_KEY");
  if (logPin.empty())
    logPin = "0123456789ABCDEF";
  _log.reset(new Log(items, logDir, logSystemName, 
    logName, logPin, logGroup));
}

void LogProfile::setProfile(const std::string &sec, 
  const std::string &attr, const std::string &val)
{
  _lp->set(sec, attr, val);
}

void LogProfile::setProfile(const string &attr, const string &val)
{
  setProfile(_section, attr, val);
}

std::string LogProfile::getProfile(const std::string &sec, 
  const std::string &attr) const
{
  return _lp->get(sec, attr);
}

string LogProfile::getProfile(const string &attr) const
{
  return getProfile(_section, attr);
}

}

