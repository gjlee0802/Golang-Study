#include <iostream>
#include <sstream>
#include <string>
#include <time.h>
#include "Crontab.hpp"

using namespace Issac;
using namespace std;

int main(void)
{
  time_t t;
  struct tm *timeCur;

  time(&t);
  timeCur = localtime(&t); /* Convert to local time. */

  ostringstream ost;
  ost << timeCur->tm_min << " " << timeCur->tm_hour << " " << timeCur->tm_mday
     << " " << timeCur->tm_mon + 1 << " " << timeCur->tm_wday;

  cout << "current time is " << ost.str() << endl << endl;

  std::string exp = "* * * * *";
  cout << exp << ": validity->" << Crontab::isValid(exp) << ", matching->" << Crontab::isRightTime(&t, exp) << endl;

  exp = "27 11 * * * *";
  cout << exp << ": validity->" << Crontab::isValid(exp) << ", matching->" << Crontab::isRightTime(&t, exp) << endl;

  exp = "39 13 * * 1";
  cout << exp << ": validity->" << Crontab::isValid(exp) << ", matching->" << Crontab::isRightTime(&t, exp) << endl;

  exp = "39 13 * * 2,1";
  cout << exp << ": validity->" << Crontab::isValid(exp) << ", matching->" << Crontab::isRightTime(&t, exp) << endl;

  cout << ost.str() << ": validity->" << Crontab::isValid(ost.str()) << ", matching->" << 
    Crontab::isRightTime(&t, ost.str()) << endl;

  return 0;
}
