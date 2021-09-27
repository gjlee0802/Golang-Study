/**
 * @file    CMP_cofirmMessage.cpp
 *
 * @desc    conf 메시지를 처리하는 function
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2002.05.07
 *
 * Revision History
 *
 * @date     2002.05.07 : Start
 *
 *
 */

#include "x509pkc.h"

#include "CMPSocket.hpp"
#include "DBPKC.hpp"
#include "DBPolicy.hpp"
#include "Log.hpp"

#include "er_define.h"

#include "RALoginProfile.hpp"
#include "CMP.hpp"
#include "CMPException.hpp"
#include "DBException.hpp"
#include "PKILogTableDefine.hpp"

//////////////////////////////////////////////////////////////////////
// CMPConfCommand Class
//////////////////////////////////////////////////////////////////////
using namespace Issac::DB;
using namespace std;

namespace Issac
{

void CMP::recvConfMessage()
{
  try
  {
    _confMessage.reset(_sock.recvPKIMessage(), ASN_Delete);
  }
  catch (Exception)
  {
    /*# ERROR : Conf 메시지 수신 실패 */
    /*# LOG : Conf 메시지 수신 실패 */
    throw CMPException(LOG_CAMSGD_FAIL_TO_RECV_CONF_N);
  }
}

void CMP::dispatchConfMessage()
{
  if (_confMessage->body->select != PKIBody_conf &&
    _confMessage->body->select != PKIBody_error)
  {
    /*# ERROR : 잘못된 Conf 메시지 */
    /*# LOG : 잘못된 Conf 메시지 */
    CMPException e(LOG_CAMSGD_INVALID_CONF_MESSAGE_N);
    e.addOpt("PKIBody의 choice 값", _confMessage->body->select-1);
    throw e;
  }
  else if (_confMessage->body->select == PKIBody_error)
    /*# ERROR : Error Message 수신 */
    /*# LOG : Error 메시지 수신 */
    /*# FIXME : RFC2510 draft bis-04에는 error 메시지 수신시 server가
     *          conf 메시지로 응답하도록 되어 있으므로, 그 점을 반영할 것인지 고려할 것
     */
    throw CMPException(LOG_CAMSGD_ERROR_MESSAGE_RECEIVED_N);

  // RA의 경우에는 CA에게 conf 메시지를 전송해야 함
  if (RALoginProfile::get())
    sendConfMessageToCA();

  // 사용자에게 성공적으로 전달 된 인증서의 상태를 'GOOD'으로 변경
  std::vector<ISSUE_CONTEXT>::iterator i;
  for (i = _issueCtx.begin(); i != _issueCtx.end(); i++)
  {
    CertResponse *certResponse = i->certResponse.get();
    int status;
    ASNInt_GetInt(&status, certResponse->status->status);
    if (status == PKIStatus_accepted || status == PKIStatus_grantedWithMods)
    {
      try
      {
        dynamic_cast<DBPKC *>(i->pkc.get())->unhold();
      }
      catch (DBException)
      {
        /*# ERROR : 인증서 상태 변경 실패 */
        /*# Log : 발급된 인증서의 상태를 변경하는데 실패 */
        LogItemSharedPtr logItem(AuthorityLoginProfile::get()->getLog()->createLogItem());
        logItem->setLogItem(
          LOG_CAMSGD_FAIL_TO_UNHOLD_CERT_N,
          "발급된 인증서 일련 번호 : %s, 인증서 정책 명 : %s",
          dynamic_cast<DBPKC *>(i->pkc.get())->getSerialNumber().c_str(),
          dynamic_cast<DBPolicy *>(i->policy.get())->name.c_str());
        logItem->setCertHolder(getLogHolderInfo(_certHolder));
        //logItem->setWorker(DBObjectBase::getSelf());
        logItem->write();
        continue;
      }

      LogItemSharedPtr logItem(AuthorityLoginProfile::get()->getLog()->createLogItem());
      switch(i->reqType)
      {
      case PKIBody_ir :
        /*# LOG : 인증서 신규 발급 */
        logItem->setLogItem(
          LOG_CAMSGD_CERTIFICATE_ISSUED_N,
          "발급된 인증서 일련 번호 : %s, 인증서 정책 명 : %s",
          dynamic_cast<DBPKC*>(i->pkc.get())->getSerialNumber().c_str(),
          dynamic_cast<DBPolicy*>(i->policy.get())->name.c_str());
        break;
      case PKIBody_cr :
        /*# LOG : 인증서 추가 발급 */
        logItem->setLogItem(
          LOG_CAMSGD_ADDITIONAL_CERTIFICATE_ISSUED_N,
          "발급된 인증서 일련 번호 : %s, 인증서 정책 명 : %s",
          dynamic_cast<DBPKC*>(i->pkc.get())->getSerialNumber().c_str(),
          dynamic_cast<DBPolicy*>(i->policy.get())->name.c_str());
        break;
      case PKIBody_kur :
        /*# LOG : 인증서 갱신 */
        logItem->setLogItem(
          LOG_CAMSGD_CERTIFICATE_RENEWED_N,
          "발급된 인증서 일련 번호 : %s, 인증서 정책 명 : %s",
          dynamic_cast<DBPKC*>(i->pkc.get())->getSerialNumber().c_str(),
          dynamic_cast<DBPolicy*>(i->policy.get())->name.c_str());
        break;
      case PKIBody_ccr :
        /*# LOG : 상호 인증용 인증서 발급 */
        logItem->setLogItem(
          LOG_CAMSGD_CERTIFICATE_ISSUED_N,
          "발급된 인증서 일련 번호 : %s, 인증서 정책 명 : %s",
          dynamic_cast<DBPKC*>(i->pkc.get())->getSerialNumber().c_str(),
          dynamic_cast<DBPolicy*>(i->policy.get())->name.c_str());
        break;
      default :
        VERIFY(false);
      }
      logItem->setRequester(getLogReqInfo(_sender, _sock.getPeerName()));
      logItem->setCertHolder(getLogHolderInfo(_certHolder));
      logItem->write();
    }
  }
}

void CMP::sendConfMessageToCA() // RA only
{
  boost::shared_ptr<PKIMessage> confMessage(
    ASN_New(PKIMessage, NULL), ASN_Delete); // to CA

  if (PKIMSG_MakeConfirm(confMessage.get(), _reqContextToCA.get(), 0) != SUCCESS);
    /*# ERROR : CA로 보낼 conf 메시지 생성 실패 */
    throw CMPException(LOG_CAMSGD_FAIL_TO_SEND_CONF_TO_CA_N);

  try
  {
    _sockToCA.sendPKIMessage(confMessage.get());
  }
  catch (...)
  {
    /*# ERROR : CA로 conf 메시지 전송 실패 */
    throw CMPException(LOG_CAMSGD_FAIL_TO_SEND_CONF_TO_CA_N);
  }
}

}
