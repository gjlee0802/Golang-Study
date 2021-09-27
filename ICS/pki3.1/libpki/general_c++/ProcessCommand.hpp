/**
 * @file     ProcessCommand.hpp
 *
 * @desc     ProcessCommand의 기본 기능을 정의하는 클래스
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */
#ifndef ISSAC_PROCESS_COMMAND_HPP_
#define ISSAC_PROCESS_COMMAND_HPP_

#include "BasicCommand.hpp"

namespace Issac
{

class ProcessCommand : public BasicCommand
{
protected:
  std::string _path;

public:
  ProcessCommand(std::string path) : _path(path)
  {
  }

  virtual ~ProcessCommand();
  virtual std::vector<BasicOutput> execute(BasicInput arg);
};

}

#endif

