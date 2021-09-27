#include <iostream>
#include <sstream>
#include <string>

#include <boost/tokenizer.hpp>

#include "Trace.h"
#include "LoginProfile.hpp"
#include "LocalProfile.hpp"
#include "ProcessCommand.hpp"
#include "LoginProcessCommand.hpp"
#include "ExternalCommandMap.hpp"
#include "FunctionCommand.hpp"
#include "Exception.hpp"
#include "SlaveCommand.hpp"

using namespace std;

namespace Issac
{

#define TMPLOG "/tmp/ctrld.log"

void ExternalCommandMap::_loadLoginProcessCommands()
{
  LocalProfile t(LoginProfile::get()->getTmplFile());

  string cmds = t.get("MAIN", "MODULE");
  boost::tokenizer< boost::escaped_list_separator<char> > tok(cmds);

  vector<string> commands;
  _getSpanningCommands("MODULE", commands);
  copy(tok.begin(), tok.end(), back_inserter(commands));

  for (vector<string>::const_iterator i = commands.begin();
      i != commands.end(); ++i)
  {
    (*this)[*i] = BasicCommandSharedPtr( new LoginProcessCommand(*i) );
  }
  // pkimgr
  if (!LoginProfile::get()->getProfile("MGR", "MODULE").empty())
    (*this)["MGR"] = BasicCommandSharedPtr( new LoginProcessCommand("MGR")
    );
}

void ExternalCommandMap::_loadMacroCommands()
{
  LocalProfile t(LoginProfile::get()->getTmplFile());

  string mcmds = t.get("MAIN", "MACRO_COMMAND");
  boost::tokenizer< boost::escaped_list_separator<char> > tok(mcmds);

  vector<string> commands;
  _getSpanningCommands("MACRO_COMMAND", commands);
  copy(tok.begin(), tok.end(), back_inserter(commands));

  for (vector<string>::const_iterator i = commands.begin();
      i != commands.end(); ++i)
  {
    string cmds = LogProfile::get()->getProfile("MACRO_COMMAND", *i);
    boost::tokenizer< boost::escaped_list_separator<char> > tok2(cmds);
    boost::shared_ptr<BasicMacroCommand> cmdptr( new BasicMacroCommand );
    for (boost::tokenizer< boost::escaped_list_separator<char> >::iterator j =
        tok2.begin(); j != tok2.end(); ++j)
    {
      if (this->find(*j) != this->end())
        cmdptr->add((*this)[*j].get());
    }
    (*this)[*i] = cmdptr;
  }
}

void ExternalCommandMap::_loadProcessCommands()
{
  LocalProfile t(LoginProfile::get()->getTmplFile());

  string cmds = t.get("MAIN", "EXTERNAL_MODULE");
  boost::tokenizer< boost::escaped_list_separator<char> > tok(cmds);

  vector<string> commands;
  _getSpanningCommands("EXTERNAL_MODULE", commands);
  copy(tok.begin(), tok.end(), back_inserter(commands));

  for (vector<string>::const_iterator i = commands.begin();
      i != commands.end(); ++i)
  {
    string path(LoginProfile::get()->getProfile("EXTERNAL_MODULE", *i));
    // 상대 경로에 대한 처리 : 현재는 ./filename.ext 와 같이 ./ 으로 시작
    // 하는 형식만 지원
    if (path.size() > 2 && path.substr(0, 2) == "./")
      path = LoginProfile::get()->getBinDir() + path.substr(1);
    (*this)[*i] = BasicCommandSharedPtr( new ProcessCommand(path) );
  }
}

void ExternalCommandMap::_loadSlaveCommands()
{
  LocalProfile t(LoginProfile::get()->getTmplFile());

  string cmds = t.get("MAIN", "SLAVE_COMMAND");
  boost::tokenizer< boost::escaped_list_separator<char> > tok(cmds);

  vector<string> commands;
  _getSpanningCommands("SLAVE_COMMAND", commands);
  copy(tok.begin(), tok.end(), back_inserter(commands));

  for (vector<string>::const_iterator i = commands.begin();
      i != commands.end(); ++i)
  {
    string ip = LogProfile::get()->getProfile(*i, "IP");
    int port = atoi(LogProfile::get()->getProfile(*i, "PORT").c_str());
    if (ip == "" or port == 0)
      throw Exception(string("SLAVE COMMAND [") + *i +
          "] 섹션의 ip, port를 얻을 수 없습니다.");
    (*this)[*i] = BasicCommandSharedPtr( new SlaveCommand(ip, port, *i) );
  }
}

string ExternalCommandMap::_get(string args) const
{
  boost::escaped_list_separator<char> sep('\\', ',', '\"');
  boost::tokenizer< boost::escaped_list_separator<char> > tok(args, sep);
  boost::tokenizer< boost::escaped_list_separator<char> >::iterator i =
    tok.begin();
  string sec, attr;
  if (i != tok.end())
    sec = *i;
  if (++i != tok.end())
    attr = *i;

  if (sec.empty() || attr.empty())
    throw Exception("잘못된 형식의 변수입니다.");

  return LoginProfile::get()->getProfile(sec, attr);
}

string ExternalCommandMap::_set(string args) const
{
  boost::escaped_list_separator<char> sep('\\', ',', '\"');
  boost::tokenizer< boost::escaped_list_separator<char> > tok(args, sep);
  boost::tokenizer< boost::escaped_list_separator<char> >::iterator i =
    tok.begin();
  string sec, attr, val;
  if (i != tok.end())
    sec = *i;
  if (++i != tok.end())
    attr = *i;
  if (++i != tok.end())
    val = *i;

  if (sec.empty() || attr.empty() || val.empty())
    throw Exception("잘못된 형식의 변수입니다. "
        "(sec,attr,val 의 형식이어야 합니다.)");

  LoginProfile::get()->setProfile(sec, attr, val);

  return "";
}

void ExternalCommandMap::_loadFunctionCommands()
{
  (*this)["SHOW"] = BasicCommandSharedPtr(
      new MemberFunctionCommand<ExternalCommandMap>(this,
      &ExternalCommandMap::_get));

  (*this)["SET"] = BasicCommandSharedPtr(
      new MemberFunctionCommand<ExternalCommandMap>(this,
      &ExternalCommandMap::_set));

  (*this)["COMMAND_LIST"] = BasicCommandSharedPtr(
      new MemberFunctionCommand<ExternalCommandMap>(this,
      &ExternalCommandMap::_getList));
}

ExternalCommandMap::ExternalCommandMap()
{
  _loadLoginProcessCommands();
  _loadProcessCommands();
  _loadFunctionCommands();
  _loadSlaveCommands();
  _loadMacroCommands();
}

std::string ExternalCommandMap::_getList(string /*dummy*/) const
{
  string ret;
  for (const_iterator i = begin(); i != end(); i++)
  {
    ret += i->first + ",";
  }
  return ret;
}

ExternalCommandMap::~ExternalCommandMap()
{
}

void ExternalCommandMap::_getSpanningCommands(const std::string &type,
    std::vector<std::string> &cmds)
{
  LocalProfile t(LoginProfile::get()->getTmplFile());

  string axis = t.get("MAIN", type + "_AXIS");
  boost::tokenizer< boost::escaped_list_separator<char> > tok(axis);

  for (boost::tokenizer< boost::escaped_list_separator<char> >::iterator i =
      tok.begin(); i != tok.end(); ++i)
  {
    string span = t.get(type + "_SPAN", *i);
    boost::tokenizer< boost::escaped_list_separator<char> > tok2(span);

    for (boost::tokenizer< boost::escaped_list_separator<char> >::iterator j =
        tok2.begin(); j != tok2.end(); ++j)
    {
      cmds.push_back(*i + *j);
    }
  }
}

}

