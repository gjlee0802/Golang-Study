/**
 * @file     Daemon.hpp
 *
 * @desc     Daemon의 기본 기능을 정의하는 클래스
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */
#ifndef ISSAC_DAEMON_HPP_
#define ISSAC_DAEMON_HPP_

#include <vector>
#include <string>
#include <map>

#include "libc_wrapper.h"

namespace Issac
{

class Daemon
{
protected:
  std::string _pidFile;
  virtual void _daemonize(std::string parentExitMsg);

public:
  Daemon();
  virtual ~Daemon();
  // in function start: _beforeDeomonize -> _daemonize -> _afterDeamonize
  virtual void start(std::string parentExitMsg); 
  virtual void beforeDaemonize() {}; // override this 
  virtual void afterDaemonize() {}; // override this 

  void makeSingleInstance(std::string pidFile);
  // 록 파일열기에 실패하면 -1, 파일은 열었지만 록이 걸려 있지 않으면 0
  // 록이 걸려 있으면 록을 건 프로세스의 pid를 리턴한다.
  static pid_t getProcPid(std::string pidFile);
};

}

#endif
