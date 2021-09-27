/**
 * @file     BasicCommand.hpp
 *
 * @desc     BasicCommand의 기본 기능을 정의하는 클래스
 *
 *           Command 구조는 BasicInput을 받아 BasicOutput을 낸다.
 *
 *           BasicCommandMap은 사용자의 명령을 받아 실제 커맨드를
 *           호출할 수 있도록 명령 스트링과 실제 커맨드를 매핑한다.
 *           명령어 자체를 커맨드의 맴버로 가지는 구조도 생각할 수 있으나
 *           그것은 활용될 것을 염두해둔 설계라 부작용이 많을 것이다.
 *           그래서 커맨드는 디자인 패턴이 정의하는 방식으로 설계했고
 *           (단지 입출력을 일반적인 경우를 커버할 수 있도록 세밀히 받고)
 *           이것을 사용하는 사람은 해당 커맨드와 명령 스트링을 매핑해서
 *           사용하도록 했다. 더우기 이 매핑된 스트링은 네트워크 커맨드에서
 *           활용된다. 즉 네트워크 저편의 사용자는 상대의 커맨드를 호출할 때
 *           이 매핑된 자료를 활용한다. 그리고 일관성을 위해서 동일한
 *           프로세스의 클라이언트 모듈도 커맨드 맵의 스트링을 활용하도록
 *           했다.
 *
 *           정리하면 커맨드 자체를 명령어와 연결하지 않고, 커맨드를 구성하는
 *           프로세스가 스트링과 연관한 맵을 가질 수 있으며, 이것을 또한 
 *           네트워크 외부에 노출할 수 있다. 그러니 프로세스 내에서 호출할 때도
 *           직접 커맨드를 호출하기 보다는 맵에서 찾아서 호출하는 방식을
 *           택하는 것이 좋다.
 *
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */
#ifndef ISSAC_BASIC_COMMAND_HPP_
#define ISSAC_BASIC_COMMAND_HPP_

#include <string>
#include <map>
#include <sys/types.h>
#include <boost/shared_ptr.hpp>

#include "Command.hpp"

namespace Issac
{

typedef std::pair<std::string, std::string> BasicInput;
typedef std::pair<int, std::string> BasicOutput;
typedef Command<BasicInput, BasicOutput> BasicCommand;
typedef MacroCommand<BasicInput, BasicOutput> BasicMacroCommand;
typedef boost::shared_ptr<BasicCommand> BasicCommandSharedPtr;

typedef std::map<std::string, BasicCommandSharedPtr> BasicCommandMap;

std::string GetStringFromBasicOutputs(const std::vector<BasicOutput> &outputs, 
    std::string outputdelim = "\n", bool addfinaldelin = false);
}

#endif

