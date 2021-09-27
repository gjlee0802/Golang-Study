#include "MultiDaemon.hpp"
#include "Trace.h"

using namespace Issac;

class TwoDaemon : public MultiDaemon
{
protected:
  int processOne() 
  {
    char buf[256];
    strcpy(buf, "Hi! I'm processing ONE\r\n");
    ::send(getSockConn().handle(), buf, strlen(buf), 0);
    ::recv(getSockConn().handle(), buf, 256, 0);
    strcpy(buf, "Ok, catch you later\r\n");
    ::send(getSockConn().handle(), buf, strlen(buf), 0);
    return 0;
  }
  int processTwo() 
  {
    char buf[256];
    strcpy(buf, "Hi! I'm processing TWO\r\n");
    ::send(getSockConn().handle(), buf, strlen(buf), 0);
    recv(getSockConn().handle(), buf, 256, 0);
    strcpy(buf, "Ok, catch you later\r\n");
    ::send(getSockConn().handle(), buf, strlen(buf), 0);
    return 0;
  }

public:
  virtual void beforeDaemonize()
  {
    registerProcess(5555, (MD_PROC)&TwoDaemon::processOne);
    registerProcess(4444, (MD_PROC)&TwoDaemon::processTwo);
  }
  virtual void afterDaemonize() {}
};

int main()
{
  try
  {
    TwoDaemon d;
    d.setSingleInstance("/tmp/mdpid");
    TRACE_N("setSingleInstance check ok");
    d.start("start...");
  }
  catch (std::exception &e)
  {
    TRACE_N(e.what());
    TRACE_LOG("/tmp/mdtest", e.what());
  }
  return 0;
}

