/**
 * @file     PKIMessageDaemon.cpp
 *
 * @desc     PKIMessageDaemon�� �⺻ ����� �����ϴ� Ŭ����
 * @author   ������(hrcho@pentasecurity.com)
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
        "�޽��� ������ �ð� �������� �����մϴ�.");
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
  // �̰��� ������ ����� �����ϱ� ������ ȣ��Ǵ� ���̴�.
  // ���⿡�� �ٽ� ��ũ�ؼ� �ϳ��� ������ ���� �ֱ������� CRL�� �߱��ϰ�
  // ������ �ϳ��� ��� �����ؼ� CMP ������Ʈ�� ó���Ѵ�.
  if ((_childpid = fork()) == 0) // child
  {
    DB::DBConnection::reconnect(); // ��ũ�� DB�� reconnect�Ѵ�.
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

  DB::DBConnection::reconnect(); // ��ũ�� DB�� reconnect�Ѵ�.
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
    // ���� �Լ� ȣ�� ���ο� �αװ� ���´�.
  }
  try
  {
    ARLCommand arl;
    arl.execute(make_pair("", ""));
  }
  catch (...)
  {
    // ���� �Լ� ȣ�� ���ο� �αװ� ���´�.
  }
  try
  {
    DCRLCommand dcrl;
    dcrl.execute(make_pair("", ""));
  }
  catch (...)
  {
    // ���� �Լ� ȣ�� ���ο� �αװ� ���´�.
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
          "CA Message�� ���� ��û��, CMP ��û�� �����ϰ�� ����ȣ��Ʈ������ "
          "�����մϴ�.");
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
          (string("CA Message ������ '") + v.getRequestID() +
          "' ó�� ��û�� ������� �ʽ��ϴ�.").c_str());
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

