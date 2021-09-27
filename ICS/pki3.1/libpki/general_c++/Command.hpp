/**
 * @file     Command.hpp
 *
 * @desc     Command의 기본 기능을 정의하는 클래스
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */
#ifndef ISSAC_COMMAND_HPP_
#define ISSAC_COMMAND_HPP_

#include <string>
#include <vector>
#include <boost/shared_ptr.hpp>

namespace Issac
{

template<class T, class C> class Command
{
public:
  virtual std::vector<C> execute(T arg) = 0;
};

template<class T, class C> class MacroCommand : public Command<T, C>
{
typedef boost::shared_ptr< Command<T, C> > CommandSharedPtr;

private:
  std::vector<CommandSharedPtr> _cmds;
  std::vector<C> _rets;

public:
  void add(Command<T, C> *cmd) { _cmds.push_back(CommandSharedPtr(cmd)); }

  virtual std::vector<C> execute(T arg)
  {
    _rets.clear();
    for (typename std::vector<CommandSharedPtr>::iterator i = _cmds.begin();
         i != _cmds.end(); i++)
    {
      std::vector<C> rets = i->get()->execute(arg);
      for (typename std::vector<C>::iterator itr = rets.begin();
           itr != rets.end(); itr++)
      {
        _rets.push_back(*itr);
      }
    }
    return _rets;
  }
  virtual ~MacroCommand() {};
};

}

#endif

