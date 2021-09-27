#include "NetworkCommand.hpp"
#include "RequestCommandValues.hpp"
#include "ResponseCommandValues.hpp"
#include "Socket.hpp"
#include "Trace.h"

namespace Issac
{

using namespace std;

boost::shared_ptr<Socket> NetworkCommand::_sock;

Socket *NetworkCommand::getSock()
{
  if (!_sock.get())
    throw Exception("할당된 소켓이 없습니다.");

  return _sock.get();
}

void NetworkCommand::setSock(Socket *sock)
{
  _sock.reset(sock);
}

NetworkCommand::NetworkCommand(const string &host, const string &reqID)
  : _host(host), _reqID(reqID)
{
}

NetworkCommand::NetworkCommand(const string &reqID)
  : _reqID(reqID)
{
}

NetworkCommand::~NetworkCommand()
{
}

std::vector<BasicOutput> NetworkCommand::execute(BasicInput input)
{ 
  std::vector<BasicOutput> rets;
  BasicOutput output;
  try
  {
    RequestCommandValues v;
    v.setRequestID(_reqID);
    v.setHost(_host);
    v.setInput(input.first, input.second);
  
    getSock()->sendLengthAndData(v.getBuffer());

    string buf;
    getSock()->recvLengthAndData(buf);
    ResponseCommandValues res;
    res.loadFromBuffer(buf);
    rets = res.getBasicOutputs();
  }
  catch (exception &e)
  {
    output.first = -1;
    if (output.second.empty())
      output.second = string("NetworkCommand: 실행 실패->") + e.what();

    rets.push_back(output);
  }

  return rets;
}

}

