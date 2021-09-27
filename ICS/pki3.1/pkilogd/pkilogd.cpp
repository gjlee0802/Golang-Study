#include <iostream>
#include <stdexcept>

#include "Trace.h"

#include "CommandLineArgs.h"
//#include "CommandStrings.hpp"
#include "LoginProfile.hpp"
#include "LogDaemon.hpp"

using namespace Issac;
using namespace std;

#define COPYRIGHT  \
         "Log Daemon\n\n" \
         "(c) Copyright 2003 Penta Security Systems Inc. All right reserved"

#define R_STATUS_RUNNING        "은(는) 이미 구동중입니다."

#define TMPLOG "/tmp/logd.log"

int main(int argc, char * const *argv)
{
  // 데몬모드가 아닐때만 배너 출력 
  if (::GetOptionValueFromArgs(argc, argv, "", "d", NULL) != 0)
    cout << COPYRIGHT << endl; 

  try
  {
    // 반드시 로그 데몬을 생성하기 전에 initAndLogin을 해야 한다.
    LoginProfile::get()->initAndLogin(argc, argv, "LOGD", "PKILOGD");
    LogDaemon d;
    try
    {
      d.makeSingleInstance(LoginProfile::get()->getPidFile().c_str());
    }
    catch (...)
    {
      cerr << LoginProfile::get()->getLogName() + R_STATUS_RUNNING <<
          endl;
      return 0;
    }
    d.start("로그 데몬을 초기화하였습니다.");
  }
  catch (exception &e)
  {
    cerr << "오류 발생: " << e.what() << endl;
    TRACE_LOG(TMPLOG, e.what());
    return -1;
  }
  catch (...)
  {
    cerr << "알 수 없는 오류" << endl;
    TRACE_LOG(TMPLOG, "알 수 없는 오류");
    return -1;
  }
  return 0;
}

