#include "SlaveCommand.hpp"
#include "RequestCommandValues.hpp"
#include "ResponseCommandValues.hpp"
#include "Socket.hpp"
#include "Trace.h"

#define TMPLOG "/tmp/libpki.log"
namespace Issac
{

using namespace std;

SlaveCommand::~SlaveCommand()
{
}

std::vector<BasicOutput> SlaveCommand::execute(BasicInput input)
{ 
  std::vector<BasicOutput> rets;
  BasicOutput output;
  try
  {
    Socket sock;
    TRACE_LOG(TMPLOG, "ip=[%s], port=[%d]", _ip.c_str(), _port);
    sock.connect(_ip, _port);
    RequestCommandValues v;
    v.setRequestID(_reqID);
    v.setInput(input.first, input.second);
  
    sock.sendLengthAndData(v.getBuffer());

    string buf;
    sock.recvLengthAndData(buf);
    ResponseCommandValues res;
    res.loadFromBuffer(buf);
    rets = res.getBasicOutputs();
  }
  catch (exception &e)
  {
    output.first = -1;
    if (output.second.empty())
      output.second = string("SlaveCommand: 실행 실패->") + e.what();

    rets.push_back(output);
  }

  return rets;
}

}

