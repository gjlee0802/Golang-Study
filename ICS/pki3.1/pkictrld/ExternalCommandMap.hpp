/**
 * @file     ExternalCommandMap.hpp
 *
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */

#ifndef ISSAC_EXTERNAL_COMMAND_HPP_
#define ISSAC_EXTERNAL_COMMAND_HPP_

// from libpki
#include "BasicCommand.hpp"

namespace Issac
{

class ExternalCommandMap : public BasicCommandMap
{
protected:
  // 반드시 initAndLogin을 호출한 후 수행해야 한다.
  // 이유는 login 후의 비밀정보를 필요로 하기 때문이다.
  // _loadMacroCommands는 나머지 함수들을 호출한후 마지막으로 호출해야한다.
  void _loadProcessCommands();
  void _loadLoginProcessCommands();
  void _loadFunctionCommands();
  void _loadSlaveCommands();
  void _loadMacroCommands();

  // command type을 위한 연결함수
  std::string _set(std::string args) const;
  std::string _get(std::string args) const;

  std::string _getList(std::string dummy) const;

  void _getSpanningCommands(const std::string &type,
      std::vector<std::string> &cmds);
public:
  ExternalCommandMap();
  virtual ~ExternalCommandMap();
};

}

#endif

