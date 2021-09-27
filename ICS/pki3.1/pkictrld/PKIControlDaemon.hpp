/**
 * @file     PKIControlDaemon.hpp
 *
 * @desc     PKIControlDaemon�� �⺻ ����� �����ϴ� Ŭ����
 * @author   ������(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */
#ifndef ISSAC_PKI_CONTROL_DAEMON_HPP_
#define ISSAC_PKI_CONTROL_DAEMON_HPP_

#include <string>
#include <unistd.h>

#include "MultiDaemon.hpp"
#include "ExternalCommandMap.hpp"
#ifndef _SLAVE
#include "DBObject.hpp"
#endif

class Socket;

namespace Issac
{

class PKIControlDaemon : public MultiDaemon
{
protected:
#ifndef _SLAVE
  static pid_t _childpid;
#endif
  static void _handleException(int signum);
  static void _terminateProcess(int signum);

  ExternalCommandMap _extCmds;

  void _processCron();
  int _processCommandRequest(); // ���� Ŀ�ǵ� ó��
#ifndef _SLAVE
  int _processDBRequest();      // DB proxy ó�� - ldap ��ü�� CommandRequest��
#endif

  void _sendResult(const std::vector<BasicOutput> &rets, Socket &sock);
#ifndef _SLAVE
  DB::DBObjectSharedPtr _getSenderPKC(const std::string &dn,
      const std::string &ser);
#endif

public:
  PKIControlDaemon();
  static void _alarmTerminate(int signum);
  virtual void beforeDaemonize();
  virtual void afterDaemonize();
};

}

#endif
