/**
 * @file     MultiDaemon.hpp
 *
 * @desc     MultiDaemon의 기본 기능을 정의하는 클래스
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */
#ifndef ISSAC_MULTI_DAEMON_IDX_HPP_
#define ISSAC_MULTI_DAEMON_IDX_HPP_

#include <vector>
#include <string>

#include "Daemon.hpp"
#include "Socket.hpp"
#include "SocketHelper.h"
#include "Exception.hpp"

#define MAX_SELECT 20

namespace Issac
{

class MultiDaemonHaveIdxError : public Exception
{
public:
  MultiDaemonHaveIdxError (const std::string &s = 
    "MultiDaemonHavePortError") : Exception(s) {}
};

class MultiDaemonHaveIdx;
typedef int (MultiDaemonHaveIdx::*MD_PROC)(int idx);

class MultiDaemonHaveIdx : public Daemon
{
protected:
  Socket _sockConn;
  std::vector<Socket> _socks;
  std::vector<int> _ports;
  int _idxProc;
  MD_PROC _procs[MAX_SELECT];

  void _callProcess(int idx); // fork and call process
  void _listen();
  void _run();
  void _bindTest();
  
public:
  MultiDaemonHaveIdx();
  virtual ~MultiDaemonHaveIdx();
  virtual void start(std::string parentExitMsg);

  // start 전에 registerProcess를 해야 한다.
  void registerProcess(int port, int (MultiDaemonHaveIdx::*proc)(int idx));

  Socket getSockConn() { return _sockConn; }
};

}

#endif

