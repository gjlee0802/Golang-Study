/**
 * @file     CRLCommand.hpp
 *
 * @desc     CRLCommand의 기본 기능을 정의하는 클래스
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.4.24
 *
 */
#ifndef ISSAC_CRL_COMMAND_HPP_
#define ISSAC_CRL_COMMAND_HPP_

#include <string>
#include <vector>

// from libpki
#include "BasicCommand.hpp"
#include "CRL.hpp"
#include "LogException.hpp"
#include "LoginProfile.hpp"

#define ISSUE_SUCCESS     "발행에 성공하였습니다."
#define NEED_NOT_UPDATE   "이 최신이어서 갱신할 필요가 없습니다. 강제로 갱신"\
                          "하려면 NOW 옵션을 붙여서 수행하세요."

#define ISSUE_NOW         "NOW"

namespace Issac
{

/* 입출력은 스트링으로 고정하고, 리시버의 타입에 따른 커맨드 탬플릿 정의 */
template<class T> class CRLCommandBase : public BasicCommand
{
public:
  virtual ~CRLCommandBase() {};
  CRLCommandBase() {};

  virtual std::vector<BasicOutput> execute(BasicInput input)
  {
    T crl;
    BasicOutput ret;

    std::transform(input.first.begin(), input.first.end(),
        input.first.begin(), ::toupper);
    if (input.first != ISSUE_NOW && !crl.checkIfNeedUpdate())
    {
      ret.second = crl.name() + NEED_NOT_UPDATE;
    }
    else
    {
      try
      {
        crl.issue();
        ret.second = ISSUE_SUCCESS;
      }
      catch (std::exception &e)
      {
        ret.second = std::string("오류 발생 : ") + e.what();
      }
    }
    if (ret.second.empty())
      ret.second = crl.name() + ISSUE_SUCCESS;

    std::vector<BasicOutput> rets;
    rets.push_back(ret);
    return rets;
  }
};

typedef CRLCommandBase<CRLProcess> CRLCommand;
typedef CRLCommandBase<ARLProcess> ARLCommand;
typedef CRLCommandBase<DCRLProcess> DCRLCommand;

}

#endif

