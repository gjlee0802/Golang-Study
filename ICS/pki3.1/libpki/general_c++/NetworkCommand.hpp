/**
 * @file     NetworkCommand.hpp
 *
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */
#ifndef ISSAC_NETWORK_COMMAND_HPP_
#define ISSAC_NETWORK_COMMAND_HPP_

#include <string>
#include <boost/shared_ptr.hpp>

#include "BasicCommand.hpp"
#include "Socket.hpp"

namespace Issac
{

class NetworkCommand : public BasicCommand
{
protected:
  static boost::shared_ptr<Socket> _sock;
  std::string _host;
  std::string _reqID;

public:
  static Socket *getSock();
  // setSock은 내부에서 shared_ptr로 관리되므로 반드시 스택 객체의 포인터로 
  // 주면 안된다. 반드시 new로 할당해야 한다.
  static void setSock(Socket* sock);
  NetworkCommand(const std::string &host, const std::string &reqID);
  NetworkCommand(const std::string &reqID);
  void set(const std::string &host, const std::string &reqID)
  {
    _host = host;
    _reqID = reqID;
  }
  void set(const std::string &reqID)
  {
    _reqID = reqID;
  }
  virtual ~NetworkCommand();
  virtual std::vector<BasicOutput> execute(BasicInput input);
};

}

#endif

