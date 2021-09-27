/**
 * @file    CMPException.hpp
 *
 * @desc    CMPException ����
 * @author  ������(hrcho@pentasecurity.com)
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
   * ��û�ڿ��� ������ Error ������ �����Ѵ�.
   *
   * @param  status           (in)  pKIStatusInfo�� Status ��(PKIStatus_accepted, ..)
   * @param  freeText         (in)  pKIStatusInfo�� statusString ��, NULL�̸� �������� ����
   * @param  failInfo         (in)  pKIStatusInfo�� failInfo ��(PKIFailureInfo_badAlg, ..)
   * @param  errCode          (in)  errorCode��, 0�̸� �������� ����
   * @param  errDetail        (in)  errorDetails��, NULL�̸� �������� ����
   */
  void setErrorMsgContent(int status, const std::string &freeText, int failInfo,
                          int errCode, const std::string &errDetail);

  /**
   * ��û�ڿ��� ������ Error ������ ��´�.
   * Error ������ �����Ǿ� ���� ���� ��쿡�� NULL�� ����
   */
  ErrorMsgContent *getErrorMsgContent() const;
protected:
  boost::shared_ptr<ErrorMsgContent> _errMsg;
};

/**
 * ��û�ڿ��� ���� �޽��� ������ �ʿ��� exception
 */
class CMPSendErrorException : public CMPException
{
public:
  CMPSendErrorException(int code);
  virtual ~CMPSendErrorException() throw() {}
};

}

#endif // ISSAC_CMP_EXCEPTION_HPP_

