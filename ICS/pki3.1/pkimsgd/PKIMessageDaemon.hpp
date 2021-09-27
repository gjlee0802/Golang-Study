/**
 * @file     PKIMessageDaemon.hpp
 *
 * @desc     PKIMessageDaemon의 기본 기능을 정의하는 클래스
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */
#ifndef ISSAC_PKI_MESSAGE_DAEMON_HPP_
#define ISSAC_PKI_MESSAGE_DAEMON_HPP_

#include <string>
#include <unistd.h>

// from libpki
#include "MultiDaemon.hpp"
#include "CMP.hpp"

namespace Issac
{

class PKIMessageDaemon : public MultiDaemon
{
protected:
  CMP _cmp;
  static void _handleException(int signum);
  static void _terminateProcess(int signum);
  static void _terminateProcessByAlarm(int signum);
  static pid_t _childpid;

  int _processCMP();
  int _processCron();
  int _processCRLRequest();

public:
  PKIMessageDaemon();
  virtual void afterDaemonize();
  virtual void beforeDaemonize();
};

}

#endif
