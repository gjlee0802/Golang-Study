/**
 * @file      Log.hpp
 *
 * @desc      Log 관련 함수 및 클래스 선언
 * @author    조현래(hrcho@pentasecurity.com)
 * @since     2002.05.22
 */

// standard headers
#include <cstdarg>
#include <cassert>
#include <sstream>
#include <boost/shared_ptr.hpp>

#include "Trace.h"

#include "Log.hpp"
#include "LogImpl.hpp"
#include "cis_cast.hpp"
#include "x509pkc.h"

#define E_S_LOG_TABLE_NOT_EXIST          "로그 테이블이 초기화되지 않았습니다."

#define TMPLOG "/tmp/auth.log"

namespace Issac
{

using namespace std;

Log::LogTable::LogTable(const LOG_TABLE_ITEMS items)
{
  if (items == NULL)
    return;
  int i = 0;
  while (items[i].code)
  {
    insert(value_type(items[i].code, items[i]));
    i++;
  }
}

string Log::format(const string &format, va_list args)
{
  #define MAX_LOG_OPT_LEN 2048 /**< argument의 최대 길이 (2KB) */
  #define MAX_LOG_BIN_OPT_LEN 256
  #define ALT_LOG_OPT_MSG "Data is too large" 
      /**< argument가 제한된 길이를 초과할 때, 대신 기록되는 메시지 */

  if (format.empty()) return string();

  ostringstream ost;
  const char *pos = format.c_str(), *newpos;
  while ((newpos = ::strchr(pos, '%')) != NULL)
  {
    ost << string(pos, newpos - pos);

    switch (*(newpos + 1))
    {
    case '%' : ost << '%'; break;
    case 'i' : ost << static_cast<int>(va_arg(args, int)); break;
    case 's' : ost << static_cast<char *>(va_arg(args, char *)); break;
    case 'u' :
      {
      const string str(type2string<ASNUTF8Str *>(va_arg(args, ASNUTF8Str *)));
      if (str.size() > MAX_LOG_OPT_LEN) ost << ALT_LOG_OPT_MSG;
      else ost << str;
      break;
      }
    case 'a' :
      {
      const string str(
        type2string<ASN *>(va_arg(args, ASN *)));
      if (str.size() > MAX_LOG_OPT_LEN) ost << ALT_LOG_OPT_MSG;
      else ost << str;
      break;
      }
    case 'o' :
      ost << type2string<Oid>(*va_arg(args, Oid *));
      break;
    case 'b' :
      {
      ASNBuf buf;
      ASNBuf_SetP(
        &buf,
        reinterpret_cast<char *>(va_arg(args, unsigned char *)),
        va_arg(args, int));
      const string str(type2string<ASNBuf *>(&buf));
      if (str.size() > MAX_LOG_OPT_LEN) ost << ALT_LOG_OPT_MSG;
      else ost << str;
      break;
      }
    case 'x' :
      {
      unsigned char *data = va_arg(args, unsigned char *);
      int len = va_arg(args, int);

      if (len > MAX_LOG_BIN_OPT_LEN) ost << ALT_LOG_OPT_MSG;
      else
      {
        ost.setf(ios::hex|ios::uppercase);
        int i;
        for (i = 0; i < len; ++i)
        {
          ost << *(data + i);
          if (i % 2 != 0) ost << ' ';
        }
        ost.unsetf(ios::hex | ios::uppercase);
      }
      break;
      }
    case 't' :
      {
      time_t val = va_arg(args, time_t);
      struct tm tmval = *localtime(&val);
      ost <<
        type2string<struct tm>(tmval, "yyyy/mm/dd HH24:MI:SS");
      break;
      }
    case '\0' : pos = newpos + 1; break;
    default : break;
    }
    pos = newpos + 2;
  }

  ost << pos;
  return ost.str();
}

void Log::LogTable::setItems(const LOG_TABLE_ITEMS items)
{
  if (items == NULL)
    return;
  int i = 0;
  while (items[i].code)
  {
    TRACE(PRETTY_TRACE_STRING);
    insert(value_type(items[i].code, items[i]));
    i++;
  }
}

Log::LogTable::~LogTable()
{
}

LOG_TABLE_ITEM Log::LogTable::getItem(int code) const
{
  const_iterator i = find(code);
  if (i == end())
  {
    LOG_TABLE_ITEM item;
    item.code = item.severity = LOG_TABLE_INVALID_CODE;
    return item;
  }
  return i->second;
}

//////////////////////////////////////////////////////////////////////
// Log Class
//////////////////////////////////////////////////////////////////////

Log::Log(const LOG_TABLE_ITEMS items, 
  string logPath, string systemName, string process, string passwd, 
  string group)
  : _impl(new LogImpl(logPath, systemName, process, "SYSTEM", passwd, group)), 
    _table(items)
{
}

Log::~Log()
{
  if (_impl != NULL)
    delete _impl;
}

void Log::write(LogItem *item)
{
  _impl->write(item->getCode(), item->getMessage());
}

void Log::setTableItems(const LOG_TABLE_ITEMS items)
{
  _table.setItems(items);
}


LogItemSharedPtr Log::createLogItem()
{
  return LogItemSharedPtr(new LogItem(*this));
}

//////////////////////////////////////////////////////////////////////
// LogItem Class
//////////////////////////////////////////////////////////////////////
void LogItem::setLogItem(int code, string opt, ...)
{
  _code = code;

  string str;

  va_list args;
  va_start(args, opt.c_str());
  str = Log::format(opt, args);
  va_end(args);

  ostringstream ost;
  LOG_TABLE_ITEM item = _log.getItem(code);

  ost << ((item.severity == LOG_SEVERITY_NOTICE) ? 'N' : 'F') 
      << ";" << item.category << ";"
      << item.desc << ";" << str << ";";

  _desc = item.desc + ":" + str;

  _logInfo = ost.str();
}

string LogItem::getDesc() const
{
  return _desc;
}

string LogItem::getMessage() const
{
  return _logInfo + _reqInfo + _holderInfo;
}

void LogItem::setCertHolder(string dn, string id)
{
  _holderInfo = dn + ";" + id;
}

void LogItem::setRequester(string peerName, string subjectDN, string entityID,
    string subjectType)
{
  _reqInfo = peerName + ";" + subjectDN + ";" + entityID + ";" + subjectType
    + ";";
}

}

