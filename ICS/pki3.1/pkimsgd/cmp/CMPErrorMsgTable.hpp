/**
 * @file    CMPErrorMsgTable.hpp
 *
 * @desc    CMP 처리시 에러가 발생한 경우
 *          사용자에게 에러 메시지 전송하는 것을 구현하기 위한 helper class
 * @author  조현래(hrcho@pentasecurity.com)
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
  std::string status;         // PKIStatusInfo의 statusString 값, NULL이면 설정하지 않음
  int         failInfo;       // PKIStatusInfo의 failInfo 값(PKIFailureInfo_badAlg, ..)
  int         errorCode;      // errorCode값, 0이면 설정하지 않음
  std::string errorDetail;    // errorDetails값, NULL이면 설정하지 않음
} CMP_ERROR_MSG_TABLE_ITEM, CMP_ERROR_MSG_TABLE_ITEMS[];

/**
 * LogCode들을 다루기 위한 singleton class
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

