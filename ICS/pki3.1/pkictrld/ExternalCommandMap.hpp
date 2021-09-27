/**
 * @file     ExternalCommandMap.hpp
 *
 * @author   ������(hrcho@pentasecurity.com)
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
  // �ݵ�� initAndLogin�� ȣ���� �� �����ؾ� �Ѵ�.
  // ������ login ���� ��������� �ʿ�� �ϱ� �����̴�.
  // _loadMacroCommands�� ������ �Լ����� ȣ������ ���������� ȣ���ؾ��Ѵ�.
  void _loadProcessCommands();
  void _loadLoginProcessCommands();
  void _loadFunctionCommands();
  void _loadSlaveCommands();
  void _loadMacroCommands();

  // command type�� ���� �����Լ�
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

