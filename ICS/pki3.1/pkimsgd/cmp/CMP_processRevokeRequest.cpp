/**
 * @file    CMP_processRevokeRequest_CA.cpp
 *
 * @desc    ���� ��û �޽���(rr)�� ó���ϴ� function
 * @author  ������(hrcho@pentasecurity.com)
 * @since   2002.05.07
 *
 * Revision History
 *
 * @date    2002.05.07 : Start
 *
 *
 */

// standard headers
#include <sstream>
#include <cassert>
#include <boost/cast.hpp>

// cis headers
#include "cmp_types.h"

// pkilib headers
#include "Trace.h"
#include "DBSubject.hpp"
#include "DBPKC.hpp"
#include "DBPolicy.hpp"
#include "CMPSocket.hpp"
#include "Log.hpp"
#include "CnK_define.hpp"

// pkimsgd headers
#include "CALoginProfile.hpp"
#include "CMP.hpp"
#include "CMPException.hpp"
#include "CMPHelper.hpp"
#include "PKILogTableDefine.hpp"

#ifdef __CYGWIN__
#define TRACEFILE "/cygdrive/c/camsgd.log"
#else
#define TRACEFILE "/tmp/camsgd.log"
#endif

using namespace std;
using namespace Issac::DB;

namespace Issac
{

/**
 * ������ ���� ��û �޽��� ó�� ������ ������ ����.
 *
 * 1. CA�� ���
 *  1) DB�κ��� ������ �������� ������ ������
 *  2) �ش� �������� �����ϰ� ���� ���°� 'Good'���� Ȯ��
 *  3) DB�κ��� �ش� ������ �������� ������ ������
 *  4) ��û�ڰ� �ش� �������� ������ ��û�� ������ �ִ��� Ȯ��
 *  5) �������� ���¸� 'REVOKE'�� ����
 *  6) ���� �޽��� ����
 * 2. RA�� ���
 *  1) DB�κ��� ������ �������� ������ ������
 *  2) �ش� �������� �����ϰ� ���� ���°� 'Good'���� Ȯ��
 *  3) DB�κ��� �ش� ������ �������� ������ ������
 *  4) ��û�ڰ� �ش� �������� ������ ��û�� ������ �ִ��� Ȯ��
 *  5) 1)~4)�� �������� ������ ��û�� ���ؼ� CA���� ������ ������ ��û
 *    - CA���� ���� ��û �޽����� RA�� ������ ��û �޽����� ������ ������ ���
 *    - CA���� ��û �޽��� ����
 *    - CA�κ��� ���� �޽��� ����
 *  6) CA�� ���� �޽��� �߿� ������ ��û�� ���� DB���� �������� ���¸� 'REVOKE'�� ����
 *  7) ���� �޽��� ����
 */
// CMPRevRequestCommand::CMPRevRequestCommand()
void CMP::processRevokeRequest()
{
  TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
  initRevokeContext();
  TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
  resolveRevDetails();
  TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
  checkSenderCanRevoke();
  TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
  if (CALoginProfile::get())
  {
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    revokeCerts();
  }
  else
  {
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    requestRevokeToCA();
  }
  TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
  makeRevokeResContest();

}

void CMP::initRevokeContext()
{
  // 1. ���� ��û�� ó���ϱ� ���� �ʱ�ȭ ���� ����
  RevReqContent *revReqContent = _reqMessage->body->choice.rr;

  if (revReqContent->size == 0)
    /*# ERROR: Error Message ����(badDataFormat : �߸��� Body) */
    /*# LOG : ������ ���� ��û �޽����� Body�� ������� */
    throw CMPSendErrorException(LOG_CAMSGD_EMPTY_REVREQUEST_BODY_N);

  // 2. ���� �޽��� body ���
  _resBody.reset(ASN_New(PKIBody, NULL), ASN_Delete);
  ASNChoice_Select(ASN_CHOICE(_resBody.get()), PKIBody_rp);

  // Memory ó���� ȿ������ ���̱� ���� PKIMessage����
  // RevReqContent�� �������� �ʰ� �ణ�� �Ǽ�(?)�� ���.
  // �Ϲ������δ� ASN_Dup���� ����Ͽ� element�� ������ ��,
  // ���� ������ element�� context item���� setting�ؾ� �ϳ�
  // (���縦 ���� ������ �� context�� ������ 2�� free�ϰ� ��)
  // ���⿡���� PKIMessage���� RevReqContent�� size�� 0���� setting�Ͽ�
  // PKIMessage�κ��� context�� pointer�� �������� ���� �̵���Ű�� ����� ����Ͽ���.
  int reqCount = revReqContent->size; // stores original size
  revReqContent->size = 0;         // discards ownership of pointers

  int reqIdx;
  for (reqIdx = 0 ; reqIdx < reqCount ;reqIdx++)
  {
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    REVOKE_CONTEXT ctx;
    _revokeCtx.push_back(ctx);

    _revokeCtx[reqIdx].reqIndex = reqIdx;
    _revokeCtx[reqIdx].revDetails.reset(revReqContent->member[reqIdx],
      ASN_Delete);
  }
  TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
}

void CMP::resolveRevDetails()
{
  for (vector<REVOKE_CONTEXT>::iterator i = _revokeCtx.begin();
    i != _revokeCtx.end(); i++)
  {
    try
    {
      if (i->revDetails->certDetails->serialNumber == NULL)
      {
        /*# ERROR: Serialnumber�� �������� ���� */
        /*# LOG : ���� ��û �޽����� ������ �������� �Ϸ� ��ȣ�� ���ԵǾ� ���� ���� */
        CMPSendErrorException e(LOG_CAMSGD_MISSING_SERIALNUMBER_TO_REVOKE_N);
        e.addOpt("�ش� RevDetails�� index(0����)", i->reqIndex);
        throw e;
      }

      // ������ ������ ������ ������
      std::ostringstream ost;
      DBObjectSharedPtr pkc;

      ost <<
        "SER='" <<
        type2string<ASNInt *>(i->revDetails->certDetails->serialNumber) << '\'';
      try
      {
        TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
        pkc = DBEntityPKC::select(ost.str().c_str());
      }
      catch (DBException)
      {
        TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
        try
        {
          pkc = DBAuthorityPKC::select(ost.str().c_str());
        }
        catch (DBException)
        {
          /*# ERROR: �ش� �������� ã�� �� ���� */
          /*# LOG : ������ �������� ã�� �� ���� */
          std::ostringstream ost;
          ost <<
              type2string<ASNInt *>(i->revDetails->certDetails->serialNumber);
          CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_FIND_CERT_TO_REVOKE_N);
          e.addOpt("���� ��û�� �� �������� �Ϸ� ��ȣ", ost.str());
          throw e;
        }
      }

      if (dynamic_cast<DBPKC*>(pkc.get())->getStat() ==
        PKIDB_PKC_STAT_REVOKED)
      {
        /*# ERROR: �̹� ������ ������ */
        /*# LOG : �̹� ������ �� �������� ���� ���� ��û */
        std::ostringstream ost;
        ost << type2string<ASNInt *>(i->revDetails->certDetails->serialNumber);
        CMPSendErrorException e(LOG_CAMSGD_CERT_ALREADY_REVOKED_N);
        e.addOpt("���� ��û�� �� �������� �Ϸ� ��ȣ", ost.str());
        throw e;
      }

      i->pkc = pkc;
      // ������ �������� �����ڿ� ���� ������ ������
      // FIXME : ������ ����ڿ� ���Ͽ� ������ ��û�ϴ� ��찡 ����ϰ�
      //         ���� ���� ������
      //         �ѹ� ������ ����ڿ� ���ؼ��� CACHE���� ����� ����Ͽ�
      //         ȿ������ ���� ��
      DBObjectSharedPtr certHolder;
      DBEntityPKC *entityPKC;
      DBAuthorityPKC *authorityPKC;

      if ((entityPKC = dynamic_cast<DBEntityPKC*>(pkc.get())) != NULL)
      {
        if ((dynamic_cast<DBSubject*>(_sender.get())->getType()) ==
          PKIDB_ENTITY_TYPE_RA)
        {
          // RA ����ڵ�
          if (dynamic_cast<DBSubject*>(_sender.get())->getSID() != entityPKC->csid)
          {
            /*# ERROR : RA�� �ڽſ��� ���� ����ڿ��� ���ؼ��� ������ ��û�� �� ���� */
            /*# LOG : ��ϱ���� �ڽſ��� ���� ����ڵ��� �������� ���ؼ��� ������ ��û�� �� ���� */
            std::ostringstream ost;
            ost <<
                type2string<ASNInt *>(i->revDetails->certDetails->serialNumber);
            CMPSendErrorException e(LOG_CAMSGD_RA_NOT_AUTHORIZED_REVOKE_N);
            e.addOpt("���� ��û�� �� �������� �Ϸ� ��ȣ", ost.str());
            throw e;
          }
          certHolder = DBObjectSharedPtr(
            new DBRAEntity(
              dynamic_cast<DBEntity*>(_sender.get()),
              entityPKC->dn));
        }
        else
        {
          ost.str("");
          ost << "SID='" << entityPKC->esid << "'";
          try
          {
            certHolder = DBEntity::select(ost.str().c_str());
          }
          catch (DBException)
          {
            /*# ERROR : DB integrity */
            /*# LOG : �ش� �������� ��ü�� ���� ������ DB���� ã�µ� ���� */
            std::ostringstream ost;
            ost <<
                type2string<ASNInt *>(i->revDetails->certDetails->serialNumber);
            CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_FIND_REVOKED_SUBJECT_BY_SID_N);
            e.addOpt("���� ��û�� �� �������� �Ϸ� ��ȣ", ost.str());
            throw e;
          }
        }
      }
      else
      {
        authorityPKC =
          boost::polymorphic_downcast<DBAuthorityPKC*>(pkc.get());
        ost.str("");
        ost << "SID='" << authorityPKC->asid << "'";
        try
        {
          certHolder = DBAuthority::select(ost.str().c_str());
        }
        catch (DBException)
        {
          /*# ERROR : DB integrity */
          /*# LOG : �ش� �������� ��ü�� ���� ������ DB���� ã�µ� ���� */
          std::ostringstream ost;
          ost <<
              type2string<ASNInt *>(i->revDetails->certDetails->serialNumber);
          CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_FIND_REVOKED_SUBJECT_BY_SID_N);
          e.addOpt("���� ��û�� �� �������� �Ϸ� ��ȣ", ost.str());
          throw e;
        }
      }
      i->certHolder = certHolder;
    }
    catch (CMPException &e)
    {
      // Log ���
      LogItemSharedPtr logItem(AuthorityLoginProfile::get()->getLog()->createLogItem());
      logItem->setLogItem(e.getCode(), e.getOpts().c_str());
      logItem->setRequester(getLogReqInfo(_sender, _sock.getPeerName()));
      //logItem->setWorker(DBObjectBase::getSelf());
      logItem->write();
      // Error response ����
      i->revStatus.reset(reinterpret_cast<PKIStatusInfo *>(
          ASN_Dup(ASN(e.getErrorMsgContent()->pKIStatusInfo))),
        ASN_Delete);
      continue;
    }
  }
}

void CMP::checkSenderCanRevoke()
{
  DBSubject *sender = dynamic_cast<DBSubject *>(_sender.get());
  DBSubject *certHolder;

  TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
  for (vector<REVOKE_CONTEXT>::iterator i = _revokeCtx.begin();
    i != _revokeCtx.end(); i++)
  {
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    if (i->revStatus.get())
        continue;
        // response�� �̹� �����Ǿ� �ִ� ���(error)

    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    try
    {
      TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
      // 1. ��û ��� ���� ��û���� ���� �˻�
      certHolder = dynamic_cast<DBSubject *>(i->certHolder.get());

      TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
      try
      {
        TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
        checkSenderPrivilege(sender, certHolder);
      }
      catch (CMPSendErrorException &e)
      {
        TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
        /*# Exception : ���� �˻� ���� */
        std::ostringstream ost;
        ost <<
              type2string<ASNInt *>(i->revDetails->certDetails->serialNumber);
        e.addOpt("���� ��û�� �� �������� �Ϸ� ��ȣ", ost.str());
        throw e;
      }
      TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);

      // 1.1. RA ������� ���, ������ RA�κ����� ���� ��û���� Ȯ��
      if (dynamic_cast<DBRAEntity*>(certHolder) != NULL)
      {
        TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
        DBEntityPKC *pkc = dynamic_cast<DBEntityPKC*>(i->pkc.get());
        DBEntity *ra = dynamic_cast<DBEntity*>(_sender.get());

        if (pkc->csid != ra->sid)
        {
          TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
          /*# ERROR : RA�� �ڽſ��� ���� ����ڿ��� ���ؼ��� ������ ��û�� �� ���� */
          /*# LOG : ��ϱ���� �ڽſ��� ���� ����ڵ��� �������� ���ؼ��� ������ ��û�� �� ���� */

          std::ostringstream ost;
          ost <<
              type2string<ASNInt *>(i->revDetails->certDetails->serialNumber);
          CMPSendErrorException e(LOG_CAMSGD_RA_NOT_AUTHORIZED_REVOKE_N);
          e.addOpt("���� ��û�� �� �������� �Ϸ� ��ȣ", ost.str());
          throw e;
        }
        TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
      }

      TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
      // 2. ��û ����� ���� �˻�( �� CA�� ��쿡�� ���� ��û �Ұ��� )
      DBAuthority *authority;
      if ((authority = dynamic_cast<DBAuthority*>(certHolder)) != NULL)
      {
        TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
        if (authority->type == PKIDB_AUTHORITY_TYPE_SELF)
        {
          TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
          /*# ERROR : �� CA�� �������� ���ؼ��� ���� ��û ���� */
          /*# LOG : �� CA�� ������ ���� ��û */
          std::ostringstream ost;
          ost <<
              type2string<ASNInt *>(i->revDetails->certDetails->serialNumber);
          CMPSendErrorException e(
            LOG_CAMSGD_REVOKE_REQUEST_FOR_THIS_CA_CERT_N);
          e.addOpt("���� ��û�� �� �������� �Ϸ� ��ȣ", ost.str());
          throw e;
        }
        TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
      }
      TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    }
    catch (CMPException& e)
    {
      TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
      // Log ���
      LogItemSharedPtr logItem(AuthorityLoginProfile::get()->getLog()->createLogItem());
      logItem->setLogItem(e.getCode(), e.getOpts().c_str());
      logItem->setRequester(getLogReqInfo(_sender, _sock.getPeerName()));
      //logItem->setWorker(DBObjectBase::getSelf());
      logItem->write();
      // Error response ����
      i->revStatus.reset(reinterpret_cast<PKIStatusInfo *>(
          ASN_Dup(ASN(e.getErrorMsgContent()->pKIStatusInfo))),
        ASN_Delete);
      continue;
    }
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
  }
}

// ca only
void CMP::revokeCerts()
{
  TRACE_LOG(TRACEFILE, "-------------------void CMP::revokeCerts()");
  for (vector<REVOKE_CONTEXT>::iterator i = _revokeCtx.begin();
    i != _revokeCtx.end(); i++)
  {
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    if (i->revStatus.get())
      continue;

    boost::shared_ptr<PentaRevDescription> revDesc;

    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    if (i->revDetails->crlEntryDetails != NULL)
    {
      // pentaRevDescription ó��
      revDesc.reset(
        Extensions_GetByType(
          NULL, i->revDetails->crlEntryDetails,
          PentaRevDescription, NID_pentaRevDescription),
        ASN_Delete);
    }

    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    try
    {
      TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
      dynamic_cast<DBPKC *>(i->pkc.get())->revoke(
        _sender,
        ReasonFlagsToReasonCode(i->revDetails->revocationReason),
        (revDesc.get() == NULL)
          ? "" : type2string<ASNUTF8Str *>(revDesc.get()).c_str() );
    }
    catch (DBException)
    {
      TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
      /*# ERROR : ������ ���� ����(DB�� ������ ���� ���� ����) */
      /*# LOG : ������ ���� ����(DB�� ������ ���� ���� ����) */
      // error response ����(not implemented)
      CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_REVOKE_CERT_IN_DB_N);
      e.addOpt("���� ��û�� �� �������� �Ϸ� ��ȣ",
        dynamic_cast<DBPKC*>(i->pkc.get())->getSerialNumber());
      throw e;
    }

    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    // PKIStatusInfo ����
    PKIStatusInfo *statusInfo = ASN_New(PKIStatusInfo, NULL);
    VERIFY(::ASNInt_SetInt(statusInfo->status, PKIStatus_accepted) == SUCCESS);
    i->revStatus.reset(statusInfo, ASN_Delete);

    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    /*# LOG : ������ ���� ���� �Ϸ� */

    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    DBEntityPKC *entityPKC =
      dynamic_cast<DBEntityPKC*>(i->pkc.get());
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    DBAuthorityPKC *authorityPKC =
      dynamic_cast<DBAuthorityPKC*>(i->pkc.get());
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    DBAuthority *authority =
      dynamic_cast<DBAuthority*>(i->certHolder.get());

    VERIFY(entityPKC || authority);
    std::ostringstream ost;

    ost <<
      "SID='" <<
      ((entityPKC != NULL) ? entityPKC->psid : authority->psid) <<
      '\'';
    DBObjectSharedPtr policy(DBPolicy::select(ost.str().c_str()));

    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    LogItemSharedPtr logItem(AuthorityLoginProfile::get()->getLog()->createLogItem());
    logItem->setLogItem(
      LOG_CAMSGD_CERTIFICATE_REVOKED_N,
      "������ ������ �Ϸ� ��ȣ : %s, ������ ��å �� : %s, �߰� ���� ���� : %s",
      dynamic_cast<DBPKC*>(i->pkc.get())->getSerialNumber().c_str(),
      dynamic_cast<DBPolicy*>(policy.get())->name.c_str(),
      ((entityPKC != NULL) ? entityPKC->rdesc : authorityPKC->rdesc).c_str());
    //logItem->setWorker(DBObjectBase::getSelf());
    logItem->setRequester(getLogReqInfo(_sender, _sock.getPeerName()));
    logItem->setCertHolder(getLogHolderInfo(i->certHolder));
    logItem->write();
  }
}

void CMP::makeRevokeResContest()
{
  TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
  RevRepContent *revResContent = _resBody->choice.rp;
  VERIFY(::ASNSeq_NewOptional(
    pASN(&revResContent->revCerts), ASN_SEQ(revResContent)) == SUCCESS);

  for (vector<REVOKE_CONTEXT>::iterator i = _revokeCtx.begin();
    i != _revokeCtx.end(); i++)
  {
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    CertId *certId = ASN_New(CertId, NULL);
    ::GenName_Set(
      certId->issuer, GeneralName_directoryName,
      AuthorityLoginProfile::get()->getCACerts().begin()->get()->tbsCertificate->subject);
    int status;
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    VERIFY(::ASNInt_GetInt(&status, i->revStatus->status) == SUCCESS);
    if (i->revDetails->certDetails->serialNumber != NULL)
      ASN_Copy(certId->serialNumber, i->revDetails->certDetails->serialNumber);
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);

    VERIFY(::ASNSeqOf_Add(
      ASN_SEQOF(revResContent->status), ASN(i->revStatus.get())) == SUCCESS);
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    VERIFY(::ASNSeqOf_AddP(
      ASN_SEQOF(revResContent->revCerts), ASN(certId)) == SUCCESS);
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
  }
  TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
}

}
