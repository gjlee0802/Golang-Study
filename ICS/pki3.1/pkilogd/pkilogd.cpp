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

#define R_STATUS_RUNNING        "��(��) �̹� �������Դϴ�."

#define TMPLOG "/tmp/logd.log"

int main(int argc, char * const *argv)
{
  // �����尡 �ƴҶ��� ��� ��� 
  if (::GetOptionValueFromArgs(argc, argv, "", "d", NULL) != 0)
    cout << COPYRIGHT << endl; 

  try
  {
    // �ݵ�� �α� ������ �����ϱ� ���� initAndLogin�� �ؾ� �Ѵ�.
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
    d.start("�α� ������ �ʱ�ȭ�Ͽ����ϴ�.");
  }
  catch (exception &e)
  {
    cerr << "���� �߻�: " << e.what() << endl;
    TRACE_LOG(TMPLOG, e.what());
    return -1;
  }
  catch (...)
  {
    cerr << "�� �� ���� ����" << endl;
    TRACE_LOG(TMPLOG, "�� �� ���� ����");
    return -1;
  }
  return 0;
}

