#include <iostream>
#include <sstream>

#include "Exception.hpp"
#include "ProcessHandler.hpp"
#include "ProcessCommand.hpp"

#include "Trace.h"

namespace Issac
{

using namespace std;

#define TMPLOG "/tmp/libpki.log"

ProcessCommand::~ProcessCommand()
{
}

std::vector<BasicOutput> ProcessCommand::execute(BasicInput arg)
{ 
  std::vector<BasicOutput> rets;
  BasicOutput output;
  try
  {
    TRACE_LOG(TMPLOG, "%s", _path.c_str());
    output.first = ProcessExecute(_path, arg.first, arg.second, output.second);
    rets.push_back(output);
  }
  catch (exception &e)
  {
    output.first = -1;
    if (output.second.empty())
    {
      ostringstream ost;
      ost << "ProcessCommand: 프로세스 실행 실패: " << e.what() << endl;
      ost << "path: " << _path << endl;
      output.second = ost.str();
    }
    rets.push_back(output);
  }
  catch (...)
  {
    output.first = -1;
    if (output.second.empty())
    {
      ostringstream ost;
      ost << "ProcessCommand: 프로세스 실행 실패: " << endl;
      ost << "path: " << _path << endl;
      output.second = ost.str();
    }
    rets.push_back(output);
  }

  return rets;
}

}

