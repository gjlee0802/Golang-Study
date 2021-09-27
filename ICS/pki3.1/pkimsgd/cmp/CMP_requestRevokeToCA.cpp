/**
 * @file    CMP_processRevokeRequest_CA.cpp
 *
 * @desc    ���� ��û �޽���(rr)�� ó���ϴ� function�� RA specific ����
 * @author  ������(hrcho@pentasecurity.com)
 * @since   2002.05.10
 *
 * Revision history
 *
 * @date    2002.05.10 : Start
 *
 *
 */

// standard headers
#include <sstream>
#include <cassert>

// cis headers
#include "x509pkc.h"
#include "pkimessage.h"

// pki headers
#include "CnK_define.hpp"
#include "DBPKC.hpp"
#include "DBPolicy.hpp"
#include "DBSubject.hpp"
#include "CMPSocket.hpp"
#include "Log.hpp"
#include "cis_cast.hpp"

// pkimsgd headers
#include "AuthorityLoginProfile.hpp"
#include "PKILogTableDefine.hpp"
#include "CMP.hpp"
#include "CMPException.hpp"
#include "CMPHelper.hpp"

#include "er_define.h"

using namespace Issac;
using namespace std;
using namespace Issac::DB;

void CMP::requestRevokeToCA()
{
  makeRevMassageToCA();
  sendAndRecvMessageWithCA();
  resolveRevResMessageFromCA();
}

void CMP::makeRevMassageToCA()
{
  int ret;

  // CA���� ���� ��û �޽����� �����Ѵ�.
  boost::shared_ptr<PKIBody> reqBody(ASN_New(PKIBody, NULL), ASN_Delete);
  VERIFY(::ASNChoice_Select(ASN_CHOICE(reqBody.get()), PKIBody_rr) == SUCCESS);

  for (vector<REVOKE_CONTEXT>::iterator i = _revokeCtx.begin();
    i != _revokeCtx.end(); i++)
  {
    if (!i->revStatus.get()) continue;

    /*# FIXME : memory copy �� ���� �Ͼ���� ������ �� */
    VERIFY(::ASNSeqOf_Add(
      ASN_SEQOF(reqBody->choice.rr),
      ASN(i->revDetails.get())) == SUCCESS);
    // ������ ��û�� ��û ������ ����
    _revokeCtxToCA.push_back(*i);
  }

  if (reqBody->choice.rr->size == 0)
    // ���� ��û�� ������ ���� ���
    return;

  PKIMessage *reqMessage = ASN_New(PKIMessage, NULL);
  PKIContext *reqContext = ASN_New(PKIContext, NULL);
  PKISenderAuthInfo *reqAuthInfo = ASN_New(PKISenderAuthInfo, NULL);

  VERIFY(::PKISenderAuthInfo_SetCertAndPriKey(
    reqAuthInfo,
    AuthorityLoginProfile::get()->getMyCnK().first.get(), // RA CnK
    AuthorityLoginProfile::get()->getMyCnK().second.get(), NULL, NID_SHA1) == SUCCESS);
    // Hash �˰��� ����

  // PKIContext ���� �������� ����
  VERIFY(::PKIContext_Set(
    reqContext, AuthorityLoginProfile::get()->getDefaultSymmAlgNid()) == SUCCESS);
  VERIFY(::ASNSeq_NewOptional(
    pASN(&reqContext->reqInfos), ASN_SEQ(reqContext)) == SUCCESS);
  int i;
  for (i = 0; i < reqBody->choice.rr->size; i++)
  {
    PKIReqInfo *reqInfo = ASN_New(PKIReqInfo, NULL);
    VERIFY(::ASNChoice_Select(
      ASN_CHOICE(reqInfo), PKIReqInfo_revReqInfo) == SUCCESS);
    VERIFY(::ASNSeqOf_AddP(
      ASN_SEQOF(reqContext->reqInfos), ASN(reqInfo)) == SUCCESS);
  }

  /*# FIXME : ��ȿ����..(PKIBody�� �������� �ʰ� ����� �� �ֵ��� �ϴ� ���� ����� ��) */
  ret = ::PKIMSG_MakePKIMessage(
    reqMessage, reqContext,
    0, reqAuthInfo, reqBody.get(), AuthorityLoginProfile::get()->getCACerts().begin()->get());
  //ASN_Del(reqAuthInfo);

  if (ret != SUCCESS)
  {
    /*# Exception : ��û �޽��� ���� ���� */
    /*# LOG : CA���� ��û �޽��� ���� ���� */
    throw CMPSendErrorException(LOG_CAMSGD_FAIL_TO_MAKE_REQUEST_MESSAGE_N);
  }

  _reqMessageToCA.reset(reqMessage, ASN_Delete);
  _reqContextToCA.reset(reqContext, ASN_Delete);
}

void CMP::resolveRevResMessageFromCA()
{
  boost::shared_ptr<PKIRepInfo> repInfo(ASN_New(PKIRepInfo, NULL), ASN_Delete);

  if (::PKIMSG_ResolveResponse(
    repInfo.get(), _reqContextToCA.get(), _resMessageFromCA.get(), 0) != SUCCESS)
    /*# Exception : CA�κ����� ���� �޽��� �ؼ� ���� */
    /*# LOG : CA�κ��� �ؼ��� �� ���� �޽��� ���� */
    /*# FIXME : �޽����� �α׷� ����� �� ����ϱ� */
    throw CMPSendErrorException(LOG_CAMSGD_INVALID_MESSAGE_FROM_CA_N);

  // Log�� ����ϱ� ���� data
  switch (repInfo->select)
  {
  case PKIRepInfo_revResponse:
    {
    RevRepContent *revResContent = repInfo->choice.revResponse; // pointer ���� Ƚ���� ���̱� ����

    for (int resIdx = 0;
      resIdx < repInfo->choice.revResponse->status->size;
      resIdx++)
    {
      REVOKE_CONTEXT &ctx = _revokeCtxToCA[resIdx];

      int status;
      VERIFY(::ASNInt_GetInt(
        &status,
        revResContent->status->member[resIdx]->status) == SUCCESS);

      try
      {
        if (status == PKIStatus_accepted ||
          status == PKIStatus_grantedWithMods)
        {
          // CA���� �������� ������ ���
          // RA DB�� ����Ǿ� �ִ� ������ ����
          boost::shared_ptr<PentaRevDescription> revDesc;

          if (ctx.revDetails->crlEntryDetails != NULL)
          {
            // pentaRevDescription ó��
            revDesc.reset(
              Extensions_GetByType(
                NULL, ctx.revDetails->crlEntryDetails,
                PentaRevDescription, NID_pentaRevDescription),
              ASN_Delete);
          }
          try
          {
            dynamic_cast<DBPKC *>(ctx.pkc.get())->revoke(_sender,
              ReasonFlagsToReasonCode(ctx.revDetails->revocationReason),
              (revDesc.get() == NULL)
                ? NULL : (type2string<ASNUTF8Str *>(revDesc.get()).c_str()));
          }
          catch (DBException)
          {
            /*# ERROR : ������ ���� ���� */
            CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_REVOKE_CERT_IN_DB_N);
            e.addOpts(
              "���� ��û�� �� �������� �Ϸ� ��ȣ : %s",
              dynamic_cast<DBPKC *>(ctx.pkc.get())->getSerialNumber().c_str());
            throw e;
          }
          // PKIStatusInfo ����
          PKIStatusInfo *statusInfo = ASN_New(PKIStatusInfo, NULL);
          VERIFY(::ASNInt_SetInt(
            statusInfo->status, PKIStatus_accepted) == SUCCESS);
          ctx.revStatus.reset(statusInfo, ASN_Delete);
          /*# LOG : ������ ���� ���� �Ϸ� */
          /* DBObjectSharedPtr certHolder(
            revContext->GetSharedPtrItem<DBObject>(
              CMPRevokeCertContext::CONTEXT_ITEM_ID_REVCERTHOLDER)); */

          DBEntityPKC *entityPKC =
            dynamic_cast<DBEntityPKC*>(ctx.pkc.get());
          DBAuthorityPKC *authorityPKC =
            dynamic_cast<DBAuthorityPKC*>(ctx.pkc.get());
          DBAuthority *authority =
            dynamic_cast<DBAuthority*>(ctx.certHolder.get());

          VERIFY(entityPKC || authority);
          std::ostringstream ost;

          ost <<
            "SID='" <<
            ((entityPKC != NULL) ? entityPKC->psid : authority->psid) <<
            '\'';
          DBObjectSharedPtr policy(
            DBPolicy::select(ost.str().c_str()));

          LogItemSharedPtr logItem(AuthorityLoginProfile::get()->getLog()->createLogItem());
          logItem->setLogItem(
            LOG_CAMSGD_CERTIFICATE_REVOKED_N,
            "������ ������ �Ϸ� ��ȣ : %s, ������ ��å �� : %s, �߰� ���� ���� : %s",
            dynamic_cast<DBPKC *>(ctx.pkc.get())->getSerialNumber().c_str(),
            dynamic_cast<DBPolicy *>(policy.get())->name.c_str(),
            ((entityPKC != NULL) ? entityPKC->rdesc : authorityPKC->rdesc).c_str());
          logItem->setRequester(getLogReqInfo(_sender, _sock.getPeerName()));
          logItem->setCertHolder(getLogHolderInfo(ctx.certHolder));
          //logItem->setWorker(DBObjectBase::getSelf());
          logItem->write();
        }
        else // status == PKIStatus_accepted || status == PKIStatus_grantedWithMods
        {
          // ���� CA�� �ִ� �������� �̹� �����Ǿ� �ִ� �����̸� RA�� ������ ����
          if (revResContent->status->member[resIdx]->failInfo != NULL)
          {
            if (::PKIFailureInfo_Get(revResContent->status->
              member[resIdx]->failInfo) == PKIFailureInfo_certRevoked)
            {
              boost::shared_ptr<PentaRevDescription> revDesc;
              if (ctx.revDetails->crlEntryDetails != NULL)
              {
                // pentaRevDescription ó��
                revDesc.reset(
                  Extensions_GetByType(
                    NULL, ctx.revDetails->crlEntryDetails,
                    PentaRevDescription, NID_pentaRevDescription),
                  ASN_Delete);
              }
              try
              {
                dynamic_cast<DBPKC*>(ctx.pkc.get())->revoke(
                  _sender,
                  ReasonFlagsToReasonCode(ctx.revDetails->revocationReason),
                  (revDesc.get() == NULL)
                    ? NULL : (type2string<ASNUTF8Str *>(revDesc.get()).c_str()));
              }
              catch (DBException)
              {
                /*# ERROR : ������ ���� ���� */
                CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_REVOKE_CERT_IN_DB_N);
                e.addOpts(
                  "���� ��û�� �� �������� �Ϸ� ��ȣ : %s",
                  dynamic_cast<DBPKC*>(ctx.pkc.get())->getSerialNumber().c_str());
                throw e;
              }
              // PKIStatusInfo ����
              PKIStatusInfo *statusInfo = ASN_New(PKIStatusInfo, NULL);
              VERIFY(::ASNInt_SetInt(
                statusInfo->status, PKIStatus_accepted) == SUCCESS);
              ctx.revStatus.reset(statusInfo, ASN_Delete);
              /*# LOG : ������ ���� ���� �Ϸ�(��, CA������ ����) */

              DBEntityPKC *entityPKC =
                dynamic_cast<DBEntityPKC*>(ctx.pkc.get());
              DBAuthorityPKC *authorityPKC =
                dynamic_cast<DBAuthorityPKC*>(ctx.pkc.get());
              DBAuthority *authority =
                dynamic_cast<DBAuthority*>(ctx.certHolder.get());

              VERIFY(entityPKC || authority);
              std::ostringstream ost;

              ost <<
                "SID='" <<
                ((entityPKC != NULL) ? entityPKC->psid : authority->psid) <<
                '\'';
              DBObjectSharedPtr policy(
                DBPolicy::select(ost.str().c_str()));

              LogItemSharedPtr logItem(AuthorityLoginProfile::get()->getLog()->createLogItem());
              logItem->setLogItem(
                LOG_CAMSGD_CERTIFICATE_REVOKED_N,
                "������ ������ �Ϸ� ��ȣ : %s, ������ ��å �� : %s, �߰� ���� ���� : %s",
                dynamic_cast<DBPKC*>(ctx.pkc.get())->getSerialNumber().c_str(),
                dynamic_cast<DBPolicy*>(policy.get())->name.c_str(),
                ((entityPKC != NULL) ? entityPKC->rdesc : authorityPKC->rdesc).c_str());
              logItem->setRequester(getLogReqInfo(_sender, _sock.getPeerName()));
              logItem->setCertHolder(getLogHolderInfo(ctx.certHolder));
              //logItem->setWorker(DBObjectBase::getSelf());
              logItem->write();
            }
          }
          else
          {
            // ���� CA�� �ִ� �������� �̹� �����Ǿ� �ִ� ���°� �ƴ� ��쿡�� �α� ���
            PKIStatusInfo *status =
              revResContent->status->member[resIdx];

            std::ostringstream ost;
            ost <<
              "������ �źε� �������� �Ϸ� ��ȣ : " <<
              dynamic_cast<DBPKC*>(ctx.pkc.get())->getSerialNumber();

            if (status->statusString != NULL &&
              status->statusString->size > 0)
            {
              ost << ", CA�κ����� ���� �޽��� ���� statusString : ";
              ost << type2string<ASNUTF8Str *>(status->statusString->member[0]);
            }
            /*# LOG : CA���� ������ ������ �źε� */
            CMPSendErrorException e(LOG_CAMSGD_CERT_REVOCATION_REJECT_BY_CA_N);
            e.addOpts(ost.str().c_str());
            throw e;
          }
        }
      }
      catch (CMPException &e)
      {
        // PKIStatusInfo ����
        PKIStatusInfo *statusInfo = reinterpret_cast<PKIStatusInfo *>(
          ::ASN_Dup(ASN(e.getErrorMsgContent()->pKIStatusInfo)));
        ctx.revStatus.reset(statusInfo, ASN_Delete);
        // Log ���
        LogItemSharedPtr logItem(AuthorityLoginProfile::get()->getLog()->createLogItem());
        logItem->setLogItem(e.getCode(), e.getOpts().c_str());
        logItem->setRequester(getLogReqInfo(_sender, _sock.getPeerName()));
        //logItem->setWorker(DBObjectBase::getSelf());
        logItem->setCertHolder(getLogHolderInfo(ctx.certHolder));
        logItem->write();
        continue;
      }
    } // for ( nReqIndex ...
    }
    break;

  case PKIRepInfo_errorResponse :
    {
    /*# ERROR : CA�κ��� ���� �޽��� ���� */
    /*# LOG : CA�κ��� Error �޽��� ���� */
    std::ostringstream ost;
    ErrorMsgContent *errorMsg = repInfo->choice.errorResponse;

    if (errorMsg->pKIStatusInfo->statusString != NULL &&
      errorMsg->pKIStatusInfo->statusString->size > 0)
    {
      ost << "statusString : ";
      ost <<
        type2string<ASNUTF8Str *>(
          errorMsg->pKIStatusInfo->statusString->member[0]);
    }

    if (errorMsg->errorCode != NULL)
    {
      if (!ost.str().empty()) ost << ", ";
      ost << "errorCode : ";
      ost << errorMsg->errorCode;
      ost << ", ";
    }

    if (errorMsg->errorDetails != NULL &&
      errorMsg->errorDetails->size > 0)
    {
      if (!ost.str().empty()) ost << ", ";
      ost << "errorDetails : ";
      ost <<
        type2string<ASNUTF8Str *>(errorMsg->errorDetails->member[0]);
    }

    CMPSendErrorException e(LOG_CAMSGD_ERROR_MESSAGE_FROM_CA_N);
    e.addOpts(ost.str().c_str());
    throw e;
    }

  default :
    VERIFY(false);
  }
}
