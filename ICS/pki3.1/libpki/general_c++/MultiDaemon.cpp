/**
 * @file     MultiDaemon.cpp
 *
 * @desc     MultiDaemon의 기본 기능을 정의하는 클래스
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */

#include <iostream>
#include <string>
#include <stdexcept>

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

#include "SocketHelper.h"
#include "MultiDaemon.hpp"
#include "Trace.h"

#ifdef __CYGWIN__
#define TRACEFILE "/cygdrive/c/multidaemon.log"
#else
#define TRACEFILE "/tmp/multidaemon.log"
#endif

namespace Issac
{

using namespace std;

MultiDaemon::MultiDaemon()
{
  _idxProc = 0;
}

MultiDaemon::~MultiDaemon()
{
}

void MultiDaemon::registerProcess(int port, int (MultiDaemon::*proc)())
{
  _ports.push_back(port);
  _procs[_idxProc++] = proc;
}

void MultiDaemon::_callProcess(int idx)
{
  struct    sockaddr_in addr;
  socklen_t lenSoc = sizeof(addr);
  unsigned int i = 0;

  struct linger   ling;
  ling.l_onoff = 1;
  ling.l_linger = 0;    
  setsockopt(_socks[idx].handle(), SOL_SOCKET, SO_LINGER, &ling, sizeof(ling));

  /*
  try
  {
  */
  _sockConn = _socks[idx].accept((struct sockaddr*)&addr, &lenSoc);
    /*
  }
  catch (...)
  {
    if (errno == EINTR)
      return;
    throw;
  }
  */

  pid_t	pid;
  if ((pid = fork()) == 0) // child
  {
    for (i = 0; i < _socks.size(); i++)
      _socks[i].close();

    try
    {
      if (_procs[idx])
        (this->*_procs[idx])();
    }
    catch (...) {}
    _sockConn.close();

    _exit(0); // 자식 프로세스는 exit 대신 _exit가 좋다. see rstevens
  }
  else if (pid > 0) // parent
  {
    _sockConn.close();
  }
}

void MultiDaemon::start(string parentExitMsg)
{
  beforeDaemonize();
  _bindTest();
  _daemonize(parentExitMsg);
  afterDaemonize();
  _listen();
  _run();
}

// 소켓을 바인드할 수 있는지 체크한다.
void MultiDaemon::_bindTest()
{
  vector<int>::size_type i;

  for (i = 0; i < _ports.size(); i++)
  {
    Socket sock;
    sock.listen(_ports[i]);
  }
}

void MultiDaemon::_listen()
{
  vector<int>::size_type i;

  _socks.clear();

  for (i = 0; i < _ports.size(); i++)
  {
    Socket sock;
    sock.listen(_ports[i]);
    _socks.push_back(sock);
  }
}

#define MAX_SUCCESSIVE_EMPTY_LOOP 3

void MultiDaemon::_run()
{
  unsigned int i;
  int maxs = 0;

  fd_set newfds, fds;
	FD_ZERO(&fds);

  for (i = 0; i < _socks.size(); i++)
  {
    maxs = std::max(maxs, _socks[i].handle());
	  FD_SET(_socks[i].handle(), &fds);
  }
  // select loop 시작
  int emptyLoop = 0;
  do
  {
    newfds = fds;
    if (select(maxs + 1, &newfds, NULL, NULL, NULL) < 0)
    {
      ++emptyLoop;
      if (errno != EINTR)
      {
        TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
        // LOG
        exit(-1);
      }
    }
    for (i = 0; i < _socks.size(); i++)
    {
      if (FD_ISSET(_socks[i].handle(), &newfds))
      {
        emptyLoop = 0;
        try
        {
          _callProcess(i);
        }
        catch (...)
        {
          TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
        }
      }
      else
      {
        TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
        ++emptyLoop;
      }
    }
  } while (1 && emptyLoop < MAX_SUCCESSIVE_EMPTY_LOOP);

  TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
  exit(1);
}

}

