/**
 * @file    CMPException.hpp
 *
 * @desc    CMPException 선언
 * @author  조현래(hrcho@pentasecurity.com)
 * @since   2003.08.06
 */

#ifndef ISSAC_CMP_EXCEPTION_HPP_
#define ISSAC_CMP_EXCEPTION_HPP_

#include "LogException.hpp"

// forward declarations for cis
typedef struct _ErrorMsgContent ErrorMsgContent;

namespace Issac
{

class CMPException : public LogException
{
public:
  CMPException(int code);
  virtual ~CMPException() throw() {}

  /**
   * 요청자에게 전달할 Error 정보를 설정한다.
   *
   * @param  status           (in)  pKIStatusInfo의 Status 값(PKIStatus_accepted, ..)
   * @param  freeText         (in)  pKIStatusInfo의 statusString 값, NULL이면 설정하지 않음
   * @param  failInfo         (in)  pKIStatusInfo의 failInfo 값(PKIFailureInfo_badAlg, ..)
   * @param  errCode          (in)  errorCode값, 0이면 설정하지 않음
   * @param  errDetail        (in)  errorDetails값, NULL이면 설정하지 않음
   */
  void setErrorMsgContent(int status, const std::string &freeText, int failInfo,
                          int errCode, const std::string &errDetail);

  /**
   * 요청자에게 전달할 Error 정보를 얻는다.
   * Error 정보가 설정되어 있지 않은 경우에는 NULL을 리턴
   */
  ErrorMsgContent *getErrorMsgContent() const;
protected:
  boost::shared_ptr<ErrorMsgContent> _errMsg;
};

/**
 * 요청자에게 에러 메시지 전송이 필요한 exception
 */
class CMPSendErrorException : public CMPException
{
public:
  CMPSendErrorException(int code);
  virtual ~CMPSendErrorException() throw() {}
};

}

#endif // ISSAC_CMP_EXCEPTION_HPP_

