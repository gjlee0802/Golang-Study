/**
 * @file     Daemon.cpp
 *
 * @desc     Daemon의 기본 기능을 정의하는 클래스
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */

#include <time.h>
#include <stdlib.h>

#include <vector>
#include <algorithm>
#include <functional>
#include <boost/tokenizer.hpp>

#include "Crontab.hpp"

namespace Issac
{

using namespace std;

bool Crontab::isRightTime(time_t *timeCur, std::string expression)
{
  struct tm *tmCur = localtime(timeCur);

  vector<string> strs;

  vector<string> mins;
  vector<string> hours;
  vector<string> days;
  vector<string> mons;
  vector<string> wdays;

  // ' ' 단위로 추출
  boost::escaped_list_separator<char> sep('\\', ' ', '"');
  boost::tokenizer< boost::escaped_list_separator<char> > tok(expression, sep);
  copy(tok.begin(), tok.end(), back_inserter(strs));
  strs.erase(remove_if(strs.begin(), strs.end(), mem_fun_ref(&string::empty)), 
      strs.end());
  if (strs.size() != 5)
    return false;

  // ',' 단위로 추출
  tok.assign(strs[0]);
  copy(tok.begin(), tok.end(), back_inserter(mins));
  tok.assign(strs[1]);
  copy(tok.begin(), tok.end(), back_inserter(hours));
  tok.assign(strs[2]);
  copy(tok.begin(), tok.end(), back_inserter(days));
  tok.assign(strs[3]);
  copy(tok.begin(), tok.end(), back_inserter(mons));
  tok.assign(strs[4]);
  copy(tok.begin(), tok.end(), back_inserter(wdays));

  vector<string>::iterator i;
  for (i = mins.begin(); i != mins.end(); i++)
  {
    if (atoi(i->c_str()) == tmCur->tm_min || *i == "*")
      break;
  }
  if (i == mins.end())
    return false;

  for (i = hours.begin(); i != hours.end(); i++)
  {
    if (atoi(i->c_str()) == tmCur->tm_hour || *i == "*")
      break;
  }
  if (i == hours.end())
    return false;

  for (i = days.begin(); i != days.end(); i++)
  {
    if (atoi(i->c_str()) == tmCur->tm_mday || *i == "*")
      break;
  }
  if (i == days.end())
    return false;

  for (i = mons.begin(); i != mons.end(); i++)
  {
    if (atoi(i->c_str()) == (tmCur->tm_mon + 1) || *i == "*")
      break;
  }
  if (i == mons.end())
    return false;

  for (i = wdays.begin(); i != wdays.end(); i++)
  {
    if (atoi(i->c_str()) == tmCur->tm_wday || 
      (atoi(i->c_str()) == 7 && tmCur->tm_wday == 0) || *i == "*")
      break;
  }
  if (i == wdays.end())
    return false;
  
  return true;
}

bool Crontab::isValid(std::string expression)
{
  vector<string> strs;

  vector<string> mins;
  vector<string> hours;
  vector<string> days;
  vector<string> mons;
  vector<string> wdays;

  for (string::iterator i = expression.begin(); i != expression.end(); i++)
  {
    if (*i != ',' && *i != ' ' && *i != '*' && (*i > '9' || *i < '0'))
      return false;
  }

  boost::escaped_list_separator<char> sep('\\', ' ', '"');
  boost::tokenizer< boost::escaped_list_separator<char> > tok(expression, sep);
  copy(tok.begin(), tok.end(), back_inserter(strs));

  if (strs.size() != 5)
    return false;

  tok.assign(strs[0]);
  copy(tok.begin(), tok.end(), back_inserter(mins));
  tok.assign(strs[1]);
  copy(tok.begin(), tok.end(), back_inserter(hours));
  tok.assign(strs[2]);
  copy(tok.begin(), tok.end(), back_inserter(days));
  tok.assign(strs[3]);
  copy(tok.begin(), tok.end(), back_inserter(mons));
  tok.assign(strs[4]);
  copy(tok.begin(), tok.end(), back_inserter(wdays));

  if (mins.size() != 1 || mins[0] != "*")
  {
    for (vector<string>::iterator i = mins.begin(); i != mins.end(); i++)
    {
      if (atoi(i->c_str()) > 59 || atoi(i->c_str()) < 0)
        return false;
    }
  }
  if (hours.size() != 1 || hours[0] != "*")
  {
    for (vector<string>::iterator i = hours.begin(); i != hours.end(); i++)
    {
      if (atoi(i->c_str()) > 23 || atoi(i->c_str()) < 0)
        return false;
    }
  }
  if (days.size() != 1 || days[0] != "*")
  {
    for (vector<string>::iterator i = days.begin(); i != days.end(); i++)
    {
      if (atoi(i->c_str()) > 31 || atoi(i->c_str()) < 0)
        return false;
    }
  }
  if (mons.size() != 1 || mons[0] != "*")
  {
    for (vector<string>::iterator i = mons.begin(); i != mons.end(); i++)
    {
      if (atoi(i->c_str()) > 12 || atoi(i->c_str()) < 0)
        return false;
    }
  }
  if (wdays.size() != 1 || wdays[0] != "*")
  {
    for (vector<string>::iterator i = wdays.begin(); i != wdays.end(); i++)
    {
      if (atoi(i->c_str()) > 7 || atoi(i->c_str()) < 0)
        return false;
    }
  }
  
  return true;
}

}
