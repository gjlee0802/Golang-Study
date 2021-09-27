/**
 * @file     LoginProcessCommand.hpp
 *
 * @desc     LoginProcessCommand의 기본 기능을 정의하는 클래스
 *           ProcessCommand중 인증 토큰을 전달해야 하는 특수한 PKI
 *           Process를 핸들링하는 커맨드로 요청자는 토큰을 input으로
 *           넘겨주지 않아도 ProcessCommand 실행시 이를 넘겨준다.
 *           아규먼트에 -d를 붙이는 여부를 컨피그 파일로 판단하고
 *           생성자에 프로세스 이름대신 MSGD 등 컨피그 파일의
 *           키를 이용한다.
 *
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */
#ifndef ISSAC_LOGIN_PROCESS_COMMAND_HPP_
#define ISSAC_LOGIN_PROCESS_COMMAND_HPP_

#include <string>

#include "ProcessCommand.hpp"

namespace Issac
{

class LoginProcessCommand : public ProcessCommand
{
protected:
  std::string _mod;

public:
  LoginProcessCommand(std::string profileKey);
  virtual ~LoginProcessCommand();
  virtual std::vector<BasicOutput> execute(BasicInput input);
};

}

#endif

