/**
 * @file     FileProcConnector.cpp
 *
 * @desc     FileProcConnector의 기본 기능을 정의하는 클래스
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */

#include <iostream>
#include <sstream>
#include <string>
#include <fstream>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef WIN32
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <algorithm>
#endif

// from libpki
#include "Trace.h"
#include "separator.h"
#include "TimeHelper.h"
#include "Exception.hpp"

#include "FileProcConnector.hpp"

namespace Issac
{

using namespace std;
using namespace Issac;

FileProcConnector::FileProcConnector()
{
}

FileProcConnector::~FileProcConnector()
{
}

void FileProcConnector::setLastAppliedFilePathAndPos(
    const std::string &filePath, const std::ios::pos_type &pos)
{
  ofstream o(getHistoryFile().c_str());
  if (!o)
  {
    throw Exception((filePath + ": can't open").c_str());
  }
  o << filePath << endl;
  o << pos;
}

void FileProcConnector::getLastAppliedFilePathAndPos(
    std::string &filePath, std::ios::pos_type &pos)
{
  ifstream file(getHistoryFile().c_str());
  if (!file)
  {
    filePath = _getTodayFilePath();
    struct stat stbuf;
    stbuf.st_size = 0;
    stat(filePath.c_str(), &stbuf);
    pos = stbuf.st_size;
    return;
  }

  file >> filePath;
  if (filePath.empty())
    filePath = _getTodayFilePath();
  int npos;
  file >> npos;
  if (npos < 0)
    pos = 0;
  else
    pos = npos;
}

void FileProcConnector::setDataFileInfo(std::string dir, std::string format, 
    std::string prefix, std::string suffix)
{
  _dataDir = dir;
  _format = format;
  _prefix = prefix;
  _suffix = suffix;
}

void FileProcConnector::setHistoryFileInfo(std::string dir, std::string key)
{
  _histDir = dir;
  _key = key;
  std::transform(_key.begin(), _key.end(), _key.begin(), ::tolower);
}

#include "separator.h"

std::string FileProcConnector::getHistoryFile()
{
  return _histDir + FILE_SEPARATOR_STR + _key + ".his";
}

std::string FileProcConnector::_getTodayFilePath()
{
  char date[128];
  return _dataDir + FILE_SEPARATOR_STR + _prefix + 
    Time_MakeString(time((time_t *)NULL), date, _format.c_str()) +
    _suffix;
}

std::string FileProcConnector::_getNextDayFilePath(std::string filePath)
{
  string::size_type pos = filePath.rfind(FILE_SEPARATOR_STR);

  string date = filePath.substr(pos + 1 + _prefix.size(), _format.size());
  time_t t = Time_MakeTime(date.c_str(), _format.c_str());
  t += 3600 * 24;
  char newdate[10];
  Time_MakeString(t, newdate, _format.c_str());
  return filePath.substr(0, pos + 1) + _prefix + newdate + _suffix;
}

bool FileProcConnector::getNextLine(std::string &line, std::string &filePath, 
    std::ios::pos_type &pos)
{
  char sline[1024];
  ifstream i(filePath.c_str());
  i.seekg(pos, ios::beg);

  sline[0] = 0;
  if (i.getline(sline, 1024), sline[0])
  {
    line = sline;
    pos = i.tellg();
    return true;
  }
  if (filePath != _getTodayFilePath())
  {
    pos = 0;
    filePath = _getNextDayFilePath(filePath);
    return getNextLine(line, filePath, pos);
  }
  return false;
}

}

