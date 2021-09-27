#include <iostream>
#include <stdexcept>

#include "Socket.hpp"
#include "Trace.h"
#include "CommandLineArgs.h"

#include "pkimsgd_build_dependent.hpp"

using namespace Issac;
using namespace std;

#define COPYRIGHT  \
         " Message Daemon\n\n" \
         "(c) Copyright 2003 Penta Security Systems Inc. All right reserved"
#define R_STATUS_RUNNING "은(는) 이미 구동중입니다."

int main(int argc, char * const *argv)
{
  // 데몬모드가 아닐때만 배너 출력
  if (::GetOptionValueFromArgs(argc, argv, "", "d", NULL) != 0)
    cout << LOGIN_PROFILE::get()->getMyName() + COPYRIGHT << endl;

  try
  {
    LOGIN_PROFILE::get()->initAndLogin(argc, argv, PROFILE_SECTION,
        MODULE_NAME, NULL);

    MESSAGE_DAEMON d;
    try
    {
      d.makeSingleInstance(LOGIN_PROFILE::get()->getPidFile().c_str());
    }
    catch (...)
    {
      cerr << AuthorityLoginProfile::get()->getLogName() + R_STATUS_RUNNING <<
          endl;
      return 0;
    }
    d.start("메시지 데몬을 초기화하였습니다.");
  }
  catch (exception &e)
  {
    cerr << "오류 발생: " << e.what() << endl;
    TRACE_LOG("/tmp/msgd.log", e.what());
    return -1;
  }
  catch (...)
  {
    cerr << "알 수 없는 오류" << endl;
    TRACE_LOG("/tmp/msgd.log", "알 수 없는 오류\n");
    return -1;
  }
  return 0;
}

