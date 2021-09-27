/**
 * @file     CRLCommand.hpp
 *
 * @desc     CRLCommand�� �⺻ ����� �����ϴ� Ŭ����
 * @author   ������(hrcho@pentasecurity.com)
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

#define ISSUE_SUCCESS     "���࿡ �����Ͽ����ϴ�."
#define NEED_NOT_UPDATE   "�� �ֽ��̾ ������ �ʿ䰡 �����ϴ�. ������ ����"\
                          "�Ϸ��� NOW �ɼ��� �ٿ��� �����ϼ���."

#define ISSUE_NOW         "NOW"

namespace Issac
{

/* ������� ��Ʈ������ �����ϰ�, ���ù��� Ÿ�Կ� ���� Ŀ�ǵ� ���ø� ���� */
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
        ret.second = std::string("���� �߻� : ") + e.what();
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

