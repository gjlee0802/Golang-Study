#include "LoginProcessCommand.hpp"
#include "ProcessHandler.hpp"
#include "IDPASSWDsValues.hpp"
#include "LoginProfile.hpp"
#include "Socket.hpp"
#include "Trace.h"

namespace Issac
{

using namespace std;

LoginProcessCommand::LoginProcessCommand(std::string profileKey)
  : ProcessCommand("")
{
  _mod = profileKey;
  _path = LoginProfile::get()->getBinDir() + 
      LoginProfile::get()->getProfile(profileKey, "MODULE");
}

LoginProcessCommand::~LoginProcessCommand()
{
}

std::vector<BasicOutput> LoginProcessCommand::execute(BasicInput input)
{ 
  // -d 옵션이 없으면 
  string::size_type pos = input.first.find("-d");
  if (pos == string::npos)
    input.first += " -d";

  if (pos != string::npos && pos != 0 && input.first[pos - 1] != ' ')
    input.first += " -d";

  IDPASSWDsValues v;
  if (LoginProfile::get())
  {
    string id, passwd;
    LoginProfile::get()->getIDPASSWD(id, passwd);
    v.setIDPASSWD(id, passwd);
  }
  else 
    throw Exception(
        "ID/Password로 로그인한 프로세스에서만 호출할 수 있습니다.");

  input.second = Socket::makeLengthAndDataBuf(v.getBuffer()) + input.second;

  return ProcessCommand::execute(input);
}

}

