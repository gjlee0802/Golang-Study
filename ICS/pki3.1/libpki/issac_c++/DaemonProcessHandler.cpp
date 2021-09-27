#include <iostream>
#include <sstream>
#include <string>

#include <stdio.h>
#include <unistd.h>
#include <signal.h>

#include <boost/tokenizer.hpp>
#include <boost/shared_array.hpp>

#include "DaemonProcessHandler.hpp"

#include "Daemon.hpp"
#include "ProcessHandler.hpp"
#include "LogProfile.hpp"

#define R_STOP                  "을(를) 종료하였습니다."
#define R_STATUS_NOT_RUNNING    "은(는) 구동중이지 않습니다."
#define R_STATUS_RUNNING        "은(는) 이미 구동중입니다."

using namespace std;

namespace Issac
{

std::string DaemonProcessStop(std::string pidFile, std::string moduleName)
{
  pid_t pid = Daemon::getProcPid(pidFile);
  if (pid > 0 && !kill(pid, SIGTERM))
    return moduleName + R_STOP;

  return moduleName + R_STATUS_NOT_RUNNING;
}

string DaemonProcessStop(string section)
{
  return DaemonProcessStop(LogProfile::get()->getPidFile(section), section);
}

string DaemonProcessStatus(string section)
{
  return DaemonProcessStatus(LogProfile::get()->getPidFile(section), section);
}

string DaemonProcessStatus(string pidFile, string moduleName)
{
  pid_t pid = Daemon::getProcPid(pidFile);
  if (pid > 0 && !kill(pid, 0))
    return moduleName + R_STATUS_RUNNING;

  return moduleName + R_STATUS_NOT_RUNNING;
}


}

