/**
 * @file     FunctionCommand.hpp
 *
 * @desc     FunctionCommand의 기본 기능을 정의하는 클래스
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */
#ifndef ISSAC_FUNCTION_COMMAND_HPP_
#define ISSAC_FUNCTION_COMMAND_HPP_

#include <string>
#include <map>
#include <vector>
#include <stdexcept>

#include "BasicCommand.hpp"

namespace Issac
{

template <class T> class MemberFunctionCommand 
  : public BasicCommand
{
protected:
  T *_receiver;
  std::string (T::*_action)(std::string) const;
  std::string _arg;

public:
  MemberFunctionCommand(T *receiver, std::string (T::*action)(std::string) 
      const, std::string arg = "") 
    : _receiver(receiver), _action(action), _arg(arg)
  {
  }

  MemberFunctionCommand(T *receiver, std::string (T::*action)(std::string)
      , std::string arg = "") 
    : _receiver(receiver), _action(action), _arg(arg)
  {
  }

  virtual ~MemberFunctionCommand() {}

  virtual std::vector<BasicOutput> execute(BasicInput input) 
  { 
    if (!_arg.empty())
      input.first = _arg;

    BasicOutput ret;
    ret.first = 0;
    try 
    {
      ret.second = (_receiver->*_action)(input.first);
    }
    catch (std::exception &e)
    {
      ret.first = -1;
      ret.second = e.what();
    }

    std::vector<BasicOutput> rets;
    rets.push_back(ret);
    return rets;
  }
};

class FunctionCommand : public BasicCommand
{
protected:
  std::string (*_action)(std::string);
  std::string _arg;

public:
  FunctionCommand(std::string (*action)(std::string), std::string arg)
    : _action(action), _arg(arg)
  {
  }

  virtual ~FunctionCommand() {}

  virtual std::vector<BasicOutput> execute(BasicInput input) 
  { 
    if (!_arg.empty())
      input.first = _arg;
    BasicOutput ret;
    ret.first = 0;
    try 
    {
      ret.second = (*_action)(input.first);
    }
    catch (std::exception &e)
    {
      ret.first = -1;
      ret.second = e.what();
    }

    std::vector<BasicOutput> rets;
    rets.push_back(ret);
    return rets;
  }
};

}

#endif

