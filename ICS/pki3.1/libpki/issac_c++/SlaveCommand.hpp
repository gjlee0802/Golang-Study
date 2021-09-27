/**
 * @file     SlaveCommand.hpp
 *
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */
#ifndef ISSAC_SLAVE_COMMAND_HPP_
#define ISSAC_SLAVE_COMMAND_HPP_

#include <string>
#include <boost/shared_ptr.hpp>

#include "BasicCommand.hpp"
#include "Socket.hpp"

namespace Issac
{

class SlaveCommand : public BasicCommand
{
protected:
  std::string _ip;
  int _port; 
  std::string _reqID;

public:
  SlaveCommand(const std::string &ip, int port, const std::string &reqID)
  {
    set(ip, port, reqID);
  }
  void set(const std::string &ip, int port, const std::string &reqID)
  {
    _ip = ip;
    _port = port;
    _reqID = reqID;
  }
  virtual ~SlaveCommand();
  virtual std::vector<BasicOutput> execute(BasicInput input);
};

}

#endif

