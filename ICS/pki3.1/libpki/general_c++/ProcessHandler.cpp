#include <iostream>
#include <sstream>

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>

#include <boost/tokenizer.hpp>
#include <boost/shared_array.hpp>

// from libpki
#include "Trace.h"
#include "libc_wrapper.h"
#include "separator.h"

#include "Socket.hpp"
#include "ProcessHandler.hpp"

using namespace std;

string __shellPath;
string __shellName;

namespace Issac
{

void SetProcessExecuteShell(std::string shellPath)
{
  if(shellPath.empty()) {
    __shellPath = "";
    __shellName = "";
  } else {
    __shellPath = shellPath;
    __shellName = __shellPath.substr(__shellPath.rfind("/") + 1, 
      __shellPath.size() - __shellPath.rfind("/") - 1);
  }
}

void MakeExecuteArgs(string path, string arg, vector<string> &args)
{
  // arg를 프로세스 실행 인자로 변화
  replace(arg.begin(), arg.end(), '\'', '\"');
  args.push_back(path);
  boost::escaped_list_separator<char> sep('\\', ' ', '\"');
  boost::tokenizer< boost::escaped_list_separator<char> > tok(arg, sep);
  copy(tok.begin(), tok.end(), back_inserter(args));
  args.erase(remove_if(args.begin(), args.end(), 
        mem_fun_ref(&string::empty)), args.end());
}

boost::shared_array<char *> MakeCharPtrs(const vector<string> &args)
{
  boost::shared_array<char *> argv(new char *[args.size() + 1]);
  memset(argv.get(), 0, sizeof(char *) * (args.size() + 1));
  for (unsigned int i = 0; i != args.size(); ++i)
    argv.get()[i] = const_cast<char *>(args[i].c_str());

  return argv;
}

int ProcessExecute(string path, string arg, string input, string &output)
{
  int fd1[2], fd2[2];
  pid_t pid;

  if (path.empty())
    throw Exception("ProcessExecute: 실행경로가 비어있습니다.");

  struct sigaction ignore, saveintr, savequit;
  sigset_t chldmask, savemask;

  ignore.sa_handler = SIG_IGN;	/* ignore SIGINT and SIGQUIT */
  sigemptyset(&ignore.sa_mask);
  ignore.sa_flags = 0;

  if (sigaction(SIGINT, &ignore, &saveintr) < 0)
    throw Exception("sigaction(SIGINT, &ignore, &savequit) < 0");
  if (sigaction(SIGQUIT, &ignore, &savequit) < 0)
    throw Exception("sigaction(SIGQUIT, &ignore, &savequit) < 0");

  sigemptyset(&chldmask);			/* now block SIGCHLD */
  sigaddset(&chldmask, SIGCHLD);
  if (sigprocmask(SIG_BLOCK, &chldmask, &savemask) < 0)
    throw Exception("sigprocmask(SIG_BLOCK, &chldmask, &savemask) < 0");

  sigfunc *childhandler = Signal(SIGCHLD, SIG_DFL);

  pipe(fd1);
  pipe(fd2);
  
  if ((pid = fork()) < 0) // 포크 오류
  {
    TRACE_LOG("/tmp/libpki.log", "ProcessExcecute: 포크 오류");
    throw Exception("ProcessExcecute: 포크 오류");
  }
  else if (pid == 0) // child
  {
    /* restore previous signal actions & reset signal mask */
    sigaction(SIGINT, &saveintr, NULL);
    sigaction(SIGQUIT, &savequit, NULL);
    sigprocmask(SIG_SETMASK, &savemask, NULL);

    close(fd1[1]);
    close(fd2[0]);

    close(0); dup2(fd1[0], STDIN_FILENO);
    close(1); dup2(fd2[1], STDOUT_FILENO);
    close(2); dup2(STDOUT_FILENO, STDERR_FILENO);

    close(fd1[0]);
    close(fd2[1]);
    
    /*// 자식의 입력을 부모의 fd1[0]으로 dup
    dup2(fd1[0], STDIN_FILENO);
    // 자식의 출력을 부모의 fd2[1]으로 dup
    dup2(fd2[1], STDOUT_FILENO);
    dup2(fd2[1], STDERR_FILENO);
 		close(fd1[1]);
 		close(fd2[0]);*/
    // 나머지 두 파이프는 자식이 종료할 때까지 입출력 도구로 쓰기때문에
    // 닫을 필요없다.

    int ret;
    vector<string> args;
    if (__shellPath.empty())
    {
      MakeExecuteArgs(path, arg, args);
      boost::shared_array<char *> argv = MakeCharPtrs(args);
      ret = execv(path.c_str(), argv.get()); 
    }
    else
    {
      TRACE("%s, %s, %s", __shellPath.c_str(), __shellName.c_str(), arg.c_str());
      args.push_back(__shellName);
      args.push_back("-c");
      args.push_back(path);

      vector<string> args_add;
      MakeExecuteArgs(path, arg, args_add);
      copy(args_add.begin(), args_add.end(), back_inserter(args));
      boost::shared_array<char *> argv = MakeCharPtrs(args);

      ret = execl(__shellPath.c_str(), __shellName.c_str(), "-c", 
          (path + " " +  arg).c_str(), NULL);
    }

    // 성공하면 프로세스가 바뀌므로 이하의 코드는 의미없다.
    // 실패하면 _exit한다.
    if (ret < 0)
    {
      TRACE_LOG("/tmp/libpki.log", "ProcessExcecute: 프로세스 실행 실패");
      cerr << "ProcessExecute: 프로세스 실행 실패" << endl << 
        "path: '" << path << "'" << ", args[1]: '" << arg.c_str()
        << "'" << endl;
      _exit(127);
    }
  }

  Signal(SIGCHLD, childhandler);

  // parent
  /* restore previous signal actions & reset signal mask */
  sigaction(SIGINT, &saveintr, NULL);
  sigaction(SIGQUIT, &savequit, NULL);
  sigprocmask(SIG_SETMASK, &savemask, NULL);

  close(fd1[0]);
  close(fd2[1]);

  int status = -1;

  // 아래의 두 파이프는 소멸자에서 닫힌다.
  try
  {
    if (!input.empty())
    {
      Socket s(fd1[1]);
      s.send(input);
    }
  }
  catch (...)
  {}
  try
  {
    Socket r(fd2[0]);
    // clild로부터의 응답을 기다림
    char buf;
    while (r.recv(&buf, 1))
      output += buf;
  }
  catch (...)
  {
  }

  while (waitpid(pid, &status, 0) < 0)
  {
    if (errno != EINTR) 
    {
      TRACE_LOG("/tmp/libpki.log", "wait error: %s\n%s", strerror(errno), PRETTY_TRACE_STRING);
      status = -1;
      break;
    }
  }

  return status;
}

}

