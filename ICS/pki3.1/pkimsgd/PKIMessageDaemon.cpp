/**
 * @file     PKIMessageDaemon.cpp
 *
 * @desc     PKIMessageDaemon의 기본 기능을 정의하는 클래스
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */

#include <iostream>
#include <string>

#include <unistd.h>
#include <fcntl.h>
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
#include "Socket.hpp"
#include "Trace.h"
#include "Exception.hpp"

#include "DBConnection.hpp"

#include "Log.hpp"
#include "RequestCommandValues.hpp"
#include "ResponseCommandValues.hpp"

#include "PKIMessageDaemon.hpp"
#include "AuthorityLoginProfile.hpp"
#include "PKILogTableDefine.hpp"
#include "CRLCommand.hpp"


#define PERIOD 60
#define TMPLOG "/tmp/msgd.log"

namespace Issac
{

using namespace std;
using namespace DB;

pid_t PKIMessageDaemon::_childpid = 0;

PKIMessageDaemon::PKIMessageDaemon()
{
}

void PKIMessageDaemon::_terminateProcessByAlarm(int signum)
{
  LogItemSharedPtr logItem(LoginProfile::get()->getLog()->createLogItem());

  logItem->setLogItem(LOG_CAMSGD_TERMINATE_BY_ALARM_N,
        "메시지 데몬이 시간 제한으로 종료합니다.");
  logItem->write();
  ::exit(1);
}

void PKIMessageDaemon::_terminateProcess(int signum)
{
  if (_childpid)
    kill(_childpid, SIGTERM);
  ::exit(0);
}

void PKIMessageDaemon::_handleException(int signum)
{
  ::abort();
}

void PKIMessageDaemon::beforeDaemonize()
{
  int port = atoi(AuthorityLoginProfile::get()->getProfile(
          "MSGD", "PORT").c_str());
  int portin = atoi(AuthorityLoginProfile::get()->getProfile(
          "MSGD", "PORT_IN").c_str());
  registerProcess(port, (MD_PROC)&PKIMessageDaemon::_processCMP);
  registerProcess(portin, (MD_PROC)&PKIMessageDaemon::_processCRLRequest);
}

void PKIMessageDaemon::afterDaemonize()
{
  // signal setting
  ::signal(SIGTERM, _terminateProcess);
  ::signal(SIGINT, _terminateProcess);
  ::signal(SIGTSTP, _terminateProcess);
  ::signal(SIGPIPE, _terminateProcess);
  ::signal(SIGUSR1, _terminateProcess);
  ::signal(SIGUSR2, _terminateProcess);
  ::signal(SIGPOLL, _terminateProcess);
  ::signal(SIGPROF, _terminateProcess);
  ::signal(SIGVTALRM, _terminateProcess);

  ::signal(SIGABRT, _handleException);
  ::signal(SIGQUIT, _handleException);
  ::signal(SIGBUS, _handleException);
  ::signal(SIGSEGV, _handleException);
  ::signal(SIGFPE, _handleException);
  ::signal(SIGILL, _handleException);
  ::signal(SIGSYS, _handleException);
  ::signal(SIGTRAP, _handleException);
  ::signal(SIGXCPU, _handleException);
  // 이곳은 소켓을 만들어 리슨하기 직전에 호출되는 곳이다.
  // 여기에서 다시 포크해서 하나는 루프를 돌며 주기적으로 CRL을 발급하고
  // 나머지 하나는 계속 진행해서 CMP 리퀘스트를 처리한다.
  if ((_childpid = fork()) == 0) // child
  {
    DB::DBConnection::reconnect(); // 포크후 DB를 reconnect한다.
    while (1)
    {
      sleep(PERIOD);
      _processCron();
    }
    exit(1);
  }
}

int PKIMessageDaemon::_processCMP()
{
  int t = atoi(AuthorityLoginProfile::get()->
      getProfile("MSGD", "TIMEOUT").c_str());
  if (t == 0)
    t = 60;
  alarm(t);
  signal(SIGALRM, _terminateProcessByAlarm);

  DB::DBConnection::reconnect(); // 포크후 DB를 reconnect한다.
  _cmp.process(static_cast<CMPSocket>(getSockConn()));

  return 0;
}

int PKIMessageDaemon::_processCron()
{
  try
  {
    CRLCommand crl;
    crl.execute(make_pair("", ""));
  }
  catch (...)
  {
    // 위의 함수 호출 내부에 로그가 남는다.
  }
  try
  {
    ARLCommand arl;
    arl.execute(make_pair("", ""));
  }
  catch (...)
  {
    // 위의 함수 호출 내부에 로그가 남는다.
  }
  try
  {
    DCRLCommand dcrl;
    dcrl.execute(make_pair("", ""));
  }
  catch (...)
  {
    // 위의 함수 호출 내부에 로그가 남는다.
  }
  return 0;
}

int PKIMessageDaemon::_processCRLRequest()
{
  DBConnection::reconnect();

  string req;
  string args, input;
  getSockConn().recvLengthAndData(req);

  RequestCommandValues v;
  ResponseCommandValues r;
  try
  {
    v.loadFromBuffer(req);
    if (getSockConn().getPeerName() != "127.0.0.1")
      throw runtime_error(
          "CA Message에 대한 요청은, CMP 요청을 제외하고는 로컬호스트에서만 "
          "가능합니다.");
  }
  catch (exception &e)
  {
    vector<BasicOutput> rets;
    rets.push_back(make_pair(-1, e.what()));
    r.setBasicOutputs(rets);
    getSockConn().sendLengthAndData(r.getBuffer());
  }

  try
  {
    if (v.getRequestID() == "CRL")
    {
      v.getInput(args, input);
      CRLCommand crl;
      r.setBasicOutputs(crl.execute(make_pair(args,input)));
    }
    else if (v.getRequestID() == "DCRL")
    {
      v.getInput(args, input);
      DCRLCommand crl;
      r.setBasicOutputs(crl.execute(make_pair(args,input)));
    }
    else if (v.getRequestID() == "ARL")
    {
      v.getInput(args, input);
      ARLCommand crl;
      r.setBasicOutputs(crl.execute(make_pair(args,input)));
    }
    else
      throw runtime_error(
          (string("CA Message 데몬은 '") + v.getRequestID() +
          "' 처리 요청을 담당하지 않습니다.").c_str());
    try
    {
      getSockConn().sendLengthAndData(r.getBuffer());
    }
    catch (...)
    {
    }
  }
  catch (exception &e)
  {
    vector<BasicOutput> rets;
    rets.push_back(make_pair(-1, e.what()));
    r.setBasicOutputs(rets);
    getSockConn().sendLengthAndData(r.getBuffer());
  }

  return 0;
}


}

