/**
 * @file    CMPErrorMsgTable.hpp
 *
 * @desc    CMP ó���� ������ �߻��� ���
 *          ����ڿ��� ���� �޽��� �����ϴ� ���� �����ϱ� ���� helper class
 * @author  ������(hrcho@pentasecurity.com)
 * @since   2002.04.10
 */

#ifndef ISSAC_CMP_ERROR_MSG_TABLE_HPP_
#define ISSAC_CMP_ERROR_MSG_TABLE_HPP_

#include <map>
#include <string>

#include "CMPStatusString_CA.hpp"
#include "CMPStatusString_RA.hpp"

namespace Issac
{

typedef struct _CMP_ERROR_MSG_TABLE_ITEM
{
  int         logCode;
  std::string status;         // PKIStatusInfo�� statusString ��, NULL�̸� �������� ����
  int         failInfo;       // PKIStatusInfo�� failInfo ��(PKIFailureInfo_badAlg, ..)
  int         errorCode;      // errorCode��, 0�̸� �������� ����
  std::string errorDetail;    // errorDetails��, NULL�̸� �������� ����
} CMP_ERROR_MSG_TABLE_ITEM, CMP_ERROR_MSG_TABLE_ITEMS[];

/**
 * LogCode���� �ٷ�� ���� singleton class
 */
class CMPErrorMsgTable : private std::map<int, CMP_ERROR_MSG_TABLE_ITEM>
{
public:
  virtual ~CMPErrorMsgTable();

  static const CMPErrorMsgTable* get();

  CMP_ERROR_MSG_TABLE_ITEM getItem(int code) const;

protected:
  // for singleton
  CMPErrorMsgTable();

  static CMPErrorMsgTable *_inst;
  inline static void _init();
};

}

#endif /* ISSAC_CMP_ERROR_MSG_TABLE_HPP_ */

