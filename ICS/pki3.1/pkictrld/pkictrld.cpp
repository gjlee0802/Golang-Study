#include <iostream>
#include <stdexcept>

#include "Socket.hpp"
#include "Trace.h"

#include "CommandLineArgs.h"
#include "Log.hpp"
#include "ControlDaemonLogTableDefine.hpp"
#include "LoginProfile.hpp"
#include "PKIControlDaemon.hpp"

#ifndef _SLAVE
#include "LoginProfileDBConnection.hpp"
#include "DBConnection.hpp"
#endif

#define R_STATUS_RUNNING        "��(��) �̹� �������Դϴ�."

using namespace Issac;
using namespace std;

#define COPYRIGHT  \
         "PKI Control Daemon\n\n" \
         "(c) Copyright 2003 Penta Security Systems Inc. All right reserved"

int main(int argc, char * const *argv)
{
  // �����尡 �ƴҶ��� ��� ���
  if (::GetOptionValueFromArgs(argc, argv, "", "d", NULL) != 0)
    cout << COPYRIGHT << endl;

  try
  {
    #include "ControlDaemonLogTableDefine.inc"
    LoginProfile::get()->initAndLogin(argc, argv, "CTRLD",
        "PKICTRLD", __ctrldLogTableItems);
#ifndef _SLAVE
    TRACE("db connect test");
    DB::LoginProfileDBConnection_Connect();
    DB::DBConnection::close();
#endif

    PKIControlDaemon d;
    try
    {
      d.makeSingleInstance(LoginProfile::get()->getPidFile().c_str());
    }
    catch (...)
    {
      cerr << LoginProfile::get()->getLogName() + R_STATUS_RUNNING << endl;
      return 0;
    }
    d.start("��Ʈ�� ������ �ʱ�ȭ�Ͽ����ϴ�.");
  }
  catch (exception &e)
  {
    LogItemSharedPtr logItem(LoginProfile::get()->getLog()->
        createLogItem());
    logItem->setLogItem(LOG_CONTROL_DAEMON_RUNTIME_ERROR_N,
        e.what());
    logItem->write();
    cerr << "���� �߻�: " << e.what() << endl;
    TRACE_LOG("/tmp/ctrld.log", e.what());
    return -1;
  }
  catch (...)
  {
    LogItemSharedPtr logItem(LoginProfile::get()->getLog()->
        createLogItem());
    logItem->setLogItem(LOG_CONTROL_DAEMON_RUNTIME_ERROR_N,
        "�� �� ���� ����");
    logItem->write();
    cerr << "�� �� ���� ����" << endl;
    TRACE_LOG("/tmp/ctrld.log", "�� �� ���� ����\n");
    return -1;
  }
  return 0;
}
