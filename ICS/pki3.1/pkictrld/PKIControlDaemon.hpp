/**
 * @file     PKIControlDaemon.hpp
 *
 * @desc     PKIControlDaemon의 기본 기능을 정의하는 클래스
 * @author   조현래(hrcho@pentasecurity.com)
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
  int _processCommandRequest(); // 각종 커맨드 처리
#ifndef _SLAVE
  int _processDBRequest();      // DB proxy 처리 - ldap 개체는 CommandRequest로
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
