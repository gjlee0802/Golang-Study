/**
 * @file     Daemon.cpp
 *
 * @desc     Daemon의 기본 기능을 정의하는 클래스
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */

#include <iostream>
#include <string>
#include <fstream>

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
#include "Daemon.hpp"
#include "libc_wrapper.h"
#include "Trace.h"
#include "Exception.hpp"

#define PID_SUFFIX ".pid"

#define TMPLOG "/tmp/libpki.log"

#define PROCESS_IS_ALIVE 0

namespace Issac
{

using namespace std;

Daemon::Daemon()
{
}

Daemon::~Daemon()
{
}

void Daemon::_daemonize(string parentExitMsg)
{
	pid_t	pid;
  if ((pid = fork()) != 0)
  {
    cout << parentExitMsg << endl;
	  exit(0);			// parent terminates
  }

  setsid();				// become session leader

  ::Signal(SIGHUP, SIG_IGN);  // see rstevens
  ::Signal(SIGCHLD, SIG_IGN);  // see rstevens

  if ((pid = fork()) != 0)
	  exit(0);			// parent terminates

  // 포크한 후 pid가 결정되므로 이곳에서 마크한다.
  int lockfd = -1;
  if (!_pidFile.empty())
  {
    lockfd = open(_pidFile.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
    write_lock(lockfd, 0, 0, 0);
    // 위에서 pid 정보가 lockfd에 저장되어야 하지만 CYGWIN에서 작동치 않아
    // 아래처럼 따로 pid를 적어준다.
    ofstream o((_pidFile + PID_SUFFIX).c_str());
    if (!o) 
    {
      throw Exception(_pidFile + PID_SUFFIX ": 파일을 열 수 없습니다.");
    }
    o << getpid();
  }

  chdir("/");       // change working directory
  umask(0);				  // clear our file mode creation mask

  int MAXFD = ::sysconf(_SC_OPEN_MAX);
  for (int i = MAXFD - 1; i >= 0; --i)
  {
    if (i != lockfd && i != 1 && i != 2)
      close(i);
  }
  // TRACE문제를 해결한다.
#ifdef NDEBUG
  ::freopen("/dev/null", "w", stdout);
  ::freopen("/dev/null", "w", stderr);
#endif
}

void Daemon::start(string parentExitMsg)
{
  beforeDaemonize();
  _daemonize(parentExitMsg);
  afterDaemonize();
}

pid_t Daemon::getProcPid(std::string pidFile)
{
  int fd = open(pidFile.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644);
  if (fd < 0)
    return -1;

 	struct stat file_info;
	int res = 0; 
  if ((res =stat((pidFile + PID_SUFFIX).c_str(), &file_info)) == -1)
  {
  	if(ENOENT == errno)
	  	return 0;
  	
    throw Exception(pidFile + PID_SUFFIX  : "파일 체크 실패 | 에러 메시지 : "strerror(errno));
  }
    
  pid_t pid;
    
  ifstream i((pidFile + PID_SUFFIX).c_str());
  
  if (i.fail())
  	throw Exception(pidFile + PID_SUFFIX ": 파일을 열 수 없습니다.");
  
  i >> pid;
	if( PROCESS_IS_ALIVE == kill(pid,0))
		return pid;

	i.close();	
  return 0;
}

void Daemon::makeSingleInstance(std::string pidFile)
{
	_pidFile = pidFile;
 
	if( getProcPid(pidFile) > 0 ) 
		throw Exception(_pidFile + ": 프로세스가 이미 구동중입니다.");
	 
	return; 
}

}

