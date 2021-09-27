/**
 * @file    CMP_cofirmMessage.cpp
 *
 * @desc    conf �޽����� ó���ϴ� function
 * @author   ������(hrcho@pentasecurity.com)
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
    /*# ERROR : Conf �޽��� ���� ���� */
    /*# LOG : Conf �޽��� ���� ���� */
    throw CMPException(LOG_CAMSGD_FAIL_TO_RECV_CONF_N);
  }
}

void CMP::dispatchConfMessage()
{
  if (_confMessage->body->select != PKIBody_conf &&
    _confMessage->body->select != PKIBody_error)
  {
    /*# ERROR : �߸��� Conf �޽��� */
    /*# LOG : �߸��� Conf �޽��� */
    CMPException e(LOG_CAMSGD_INVALID_CONF_MESSAGE_N);
    e.addOpt("PKIBody�� choice ��", _confMessage->body->select-1);
    throw e;
  }
  else if (_confMessage->body->select == PKIBody_error)
    /*# ERROR : Error Message ���� */
    /*# LOG : Error �޽��� ���� */
    /*# FIXME : RFC2510 draft bis-04���� error �޽��� ���Ž� server��
     *          conf �޽����� �����ϵ��� �Ǿ� �����Ƿ�, �� ���� �ݿ��� ������ ����� ��
     */
    throw CMPException(LOG_CAMSGD_ERROR_MESSAGE_RECEIVED_N);

  // RA�� ��쿡�� CA���� conf �޽����� �����ؾ� ��
  if (RALoginProfile::get())
    sendConfMessageToCA();

  // ����ڿ��� ���������� ���� �� �������� ���¸� 'GOOD'���� ����
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
        /*# ERROR : ������ ���� ���� ���� */
        /*# Log : �߱޵� �������� ���¸� �����ϴµ� ���� */
        LogItemSharedPtr logItem(AuthorityLoginProfile::get()->getLog()->createLogItem());
        logItem->setLogItem(
          LOG_CAMSGD_FAIL_TO_UNHOLD_CERT_N,
          "�߱޵� ������ �Ϸ� ��ȣ : %s, ������ ��å �� : %s",
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
        /*# LOG : ������ �ű� �߱� */
        logItem->setLogItem(
          LOG_CAMSGD_CERTIFICATE_ISSUED_N,
          "�߱޵� ������ �Ϸ� ��ȣ : %s, ������ ��å �� : %s",
          dynamic_cast<DBPKC*>(i->pkc.get())->getSerialNumber().c_str(),
          dynamic_cast<DBPolicy*>(i->policy.get())->name.c_str());
        break;
      case PKIBody_cr :
        /*# LOG : ������ �߰� �߱� */
        logItem->setLogItem(
          LOG_CAMSGD_ADDITIONAL_CERTIFICATE_ISSUED_N,
          "�߱޵� ������ �Ϸ� ��ȣ : %s, ������ ��å �� : %s",
          dynamic_cast<DBPKC*>(i->pkc.get())->getSerialNumber().c_str(),
          dynamic_cast<DBPolicy*>(i->policy.get())->name.c_str());
        break;
      case PKIBody_kur :
        /*# LOG : ������ ���� */
        logItem->setLogItem(
          LOG_CAMSGD_CERTIFICATE_RENEWED_N,
          "�߱޵� ������ �Ϸ� ��ȣ : %s, ������ ��å �� : %s",
          dynamic_cast<DBPKC*>(i->pkc.get())->getSerialNumber().c_str(),
          dynamic_cast<DBPolicy*>(i->policy.get())->name.c_str());
        break;
      case PKIBody_ccr :
        /*# LOG : ��ȣ ������ ������ �߱� */
        logItem->setLogItem(
          LOG_CAMSGD_CERTIFICATE_ISSUED_N,
          "�߱޵� ������ �Ϸ� ��ȣ : %s, ������ ��å �� : %s",
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
    /*# ERROR : CA�� ���� conf �޽��� ���� ���� */
    throw CMPException(LOG_CAMSGD_FAIL_TO_SEND_CONF_TO_CA_N);

  try
  {
    _sockToCA.sendPKIMessage(confMessage.get());
  }
  catch (...)
  {
    /*# ERROR : CA�� conf �޽��� ���� ���� */
    throw CMPException(LOG_CAMSGD_FAIL_TO_SEND_CONF_TO_CA_N);
  }
}

}
