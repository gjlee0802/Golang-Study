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
#define R_STATUS_RUNNING "��(��) �̹� �������Դϴ�."

int main(int argc, char * const *argv)
{
  // �����尡 �ƴҶ��� ��� ���
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
    d.start("�޽��� ������ �ʱ�ȭ�Ͽ����ϴ�.");
  }
  catch (exception &e)
  {
    cerr << "���� �߻�: " << e.what() << endl;
    TRACE_LOG("/tmp/msgd.log", e.what());
    return -1;
  }
  catch (...)
  {
    cerr << "�� �� ���� ����" << endl;
    TRACE_LOG("/tmp/msgd.log", "�� �� ���� ����\n");
    return -1;
  }
  return 0;
}

