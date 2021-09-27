/**
 * @file    CMP_recvCertsFromCA.cpp
 *
 * @desc    �������� �߱� Ȥ�� CA�� �߱� ��û ������ �ϴ� function�� RA specific ����
 * @author   ������(hrcho@pentasecurity.com)
 * @since    2002.05.08
 *
 * Revision History
 *
 * @date     2002.05.08 : Start
 *
 *
 */

// standard headers
#include <sstream>
#include <cassert>
#include <boost/cast.hpp>

// cis headers
#include "pkimessage.h"
#include "asn1.h"

// pkilib headers
#include "CMPSocket.hpp"
#include "DBSubject.hpp"
#include "DBPKC.hpp"
#include "DBException.hpp"
#include "DBPolicy.hpp"
#include "Socket.hpp"
#include "Log.hpp"
#include "CnK_define.hpp"

// pkimsgd headers
#include "AuthorityLoginProfile.hpp"
#include "CMP.hpp"
#include "CMPException.hpp"
#include "PKILogTableDefine.hpp"

#include "er_define.h"

using namespace std;
using namespace Issac::DB;

namespace Issac
{

void CMP::recvCertsFromCA()
{
  int ret;

  boost::shared_ptr<PKIBody> reqBody(
    ASN_New(PKIBody, NULL), ASN_Delete);
  VERIFY(::ASNChoice_Select(
    ASN_CHOICE(reqBody.get()), _reqMessage.get()->body->select) == SUCCESS);

  for (vector<ISSUE_CONTEXT>::iterator i = _issueCtx.begin();
    i != _issueCtx.end(); i++)
  {
    if (i->certResponse.get())
      continue;

    try
    {
      makeCertReq(*i);
    }
    catch (CMPException &e)
    {
      LogItemSharedPtr logItem(AuthorityLoginProfile::get()->getLog()->createLogItem());

      logItem->setLogItem(e.getCode(), e.getOpts());
      logItem->setRequester(getLogReqInfo(_sender, _sock.getPeerName()));
      //logItem->setWorker(DBObjectBase::getSelf());
      logItem->setCertHolder(getLogHolderInfo(_certHolder));
      logItem->write();

      // error response ����
      VERIFY(e.getErrorMsgContent());
      CertReqMessages *certReqMessages =
        _reqMessage.get()->body->choice.ir; // union�̱� ������ ir, cr, ccr, kur�� ��� ����
      CertResponse *errorResponse = ASN_New(CertResponse, NULL);
      ASN_Copy(
        errorResponse->certReqId,
        certReqMessages->member[i->reqIndex]->certReq->certReqId);
      ASN_Copy(
        errorResponse->status,
        e.getErrorMsgContent()->pKIStatusInfo);
      i->certResponse.reset(errorResponse, ASN_Delete);
      continue;
    }
    _issueCtxToCA.push_back(*i);

    // FIXME : ��ȿ����..(AddP�� �ϰ� ���߿� �������� ����� ��� ���� ����� �� ��)
    VERIFY(::ASNSeqOf_Add(
      ASN_SEQOF(reqBody->choice.ir), ASN(i->certReqMsgToCA.get())) == SUCCESS);
      // choice�̹Ƿ� ir, kur, ccr, cr�� ����
  }

  if (reqBody->choice.ir->size == 0)
  {
    // �߱��� ��û�� ������ ���� ���
    return;
  }

  CnKSharedPtr raCnK(AuthorityLoginProfile::get()->getMyCnK());
  Certificate *caCert = AuthorityLoginProfile::get()->getCACerts().begin()->get();

  PKIMessage *reqMessage = ASN_New(PKIMessage, NULL);
  PKIContext *reqContext = ASN_New(PKIContext, NULL);
  PKISenderAuthInfo *reqAuthInfo = ASN_New(PKISenderAuthInfo, NULL);

  ::PKISenderAuthInfo_SetCertAndPriKey(
    reqAuthInfo,
    raCnK.first.get(), raCnK.second.get(), NULL, NID_SHA1); // Hash �˰��� ����
  // PKIContext ���� �������� ����
  VERIFY(::PKIContext_Set(
    reqContext, AuthorityLoginProfile::get()->getDefaultSymmAlgNid()) == SUCCESS);
  VERIFY(::ASNSeq_NewOptional(
    pASN(&reqContext->reqInfos), ASN_SEQ(reqContext)) == SUCCESS);
  int i;
  for (i = 0; i < reqBody->choice.ir->size; i++)
  {
    PKIReqInfo *reqInfo = ASN_New(PKIReqInfo, NULL);
    VERIFY(::ASNChoice_Select(
      ASN_CHOICE(reqInfo), PKIReqInfo_certReqInfo) == SUCCESS);
    ASN_Copy(reqInfo->choice.certReqInfo,
      _issueCtxToCA[i].reqCertInfoToCA.get());
    VERIFY(::ASNSeqOf_AddP(
      ASN_SEQOF(reqContext->reqInfos), ASN(reqInfo)) == SUCCESS);
  }

  /*# FIXME : ��ȿ����..(PKIBody�� �������� �ʰ� ����� �� �ֵ��� �ϴ� ���� ����� ��) */
  ret = ::PKIMSG_MakePKIMessage(
    reqMessage, reqContext,
    0, reqAuthInfo, reqBody.get(), caCert);
  ASN_Del(reqAuthInfo);

  if (ret != SUCCESS)
  {
    ASN_Del(reqMessage);
    ASN_Del(reqContext);
    /*# Exception : ��û �޽��� ���� ���� */
    throw CMPSendErrorException(LOG_CAMSGD_FAIL_TO_MAKE_REQUEST_MESSAGE_N);
  }

  _reqMessageToCA.reset(reqMessage, ASN_Delete);
  _reqContextToCA.reset(reqContext, ASN_Delete);

  // FIXME : MacroCommand�� ������ ��
  requestCertsToCA();
}

void CMP::makeCertReq(ISSUE_CONTEXT &ctx)
{
  int ret;
  /**
   * RA���� CA�� ��û�� �� ������ ������� ��û �޽������� ������ ������ �����Ͽ�
   * ������ ��û �޽����� �����Ѵ�.
   *
   * 1. certReq ��
   * 1.1. certTemplate ��
   *    - certTemplate ���� subject ���� ���� ���, RA���� �߰��Ѵ�.
   *    - certTemplate ���� extension�� subjectAlternativeName�� �߰�
   * 1.2. controls ��
   *    - control �߿��� PKIArchiveOpt�� CA ����Ű�� ����Ͽ� �����Ǿ� �ִ� ��쿡��
   *      �� ���� �״�� CA���� �����ϰ�, secretkey�� ����Ͽ� �����Ǿ� �ִ� ��쿡��
   *      �� ���� CA�� ����Ű�� ��ȣȭ�Ͽ� ���Ӱ� PKIArchiveOpt�� �����Ѵ�.
   *    - controls �� ���� penta_at_cmp_keyPolicyId�� ���� ��쿡��
   *      ���Ӱ� �����Ͽ� �߰��Ѵ�.
   * 2. POP ��
   *  - POP�� �����Ű�� CA�� ����Ű�� ��ȣȭ�Ͽ� �����Ͽ� �̷������ ��츦 �����ϰ��
   *    RA���� POP������ �̷�����Ƿ� POP_Technique_RAVerified�� POP���� ����.
   *
   */

  boost::shared_ptr<CertReqMsg> certReqMsg = ctx.certReqMsg;
  PKIReqCertInfo *reqCertInfo = ctx.reqCertInfo.get();

  DBSubject *certHolder = dynamic_cast<DBSubject *>(
    ctx.certHolder.get());
  DBPolicy *policy = dynamic_cast<DBPolicy *>(
    ctx.policy.get());
  boost::shared_ptr<PKIReqCertInfo> newReqCertInfo(
    ASN_New(PKIReqCertInfo, NULL), ASN_Delete);

  // 1. certTemplate �� ����
  // 1.1. subject ��
  if (certReqMsg->certReq->certTemplate->subject == NULL)
  {
    VERIFY(::ASNSeq_NewOptional(
      pASN(&certReqMsg->certReq->certTemplate->subject),
        ASN_SEQ(certReqMsg->certReq->certTemplate)) == SUCCESS);
    ret = ::Name_SetByStr(
      certReqMsg->certReq->certTemplate->subject,
      certHolder->getDN().c_str());
    if (ret != SUCCESS)
    {
      /*# Exception : �߸��� DB �� DN �� */
      CMPSendErrorException e(LOG_CAMSGD_INVALID_SUBJECT_DN_IN_DB_N);
      e.addOpt("�߱� ��� DN", certHolder->getDN());
      throw e;
    }
  }
  // 1.2. subjectAltName ��
  if (certReqMsg->certReq->certTemplate->extensions == NULL)
  {
    if (certHolder->getSubAltName() != NULL)
    {
      VERIFY(::ASNSeq_NewOptional(
        pASN(&certReqMsg->certReq->certTemplate->extensions),
        ASN_SEQ(certReqMsg->certReq->certTemplate)) == SUCCESS);
      VERIFY(::Extensions_AddByNid(
        certReqMsg->certReq->certTemplate->extensions,
        NID_subjectAltName, 0 /* non-critical */,
        ASN(certHolder->getSubAltName())) == SUCCESS);
    }
  }
  else
  {
    SubjectAltName *subjectAltName;
    subjectAltName = Extensions_GetByType(
      NULL,
      certReqMsg->certReq->certTemplate->extensions,
      SubjectAltName, NID_subjectAltName);
    if (subjectAltName == NULL)
    {
      if (certHolder->getSubAltName() != NULL)
      {
        VERIFY(::Extensions_AddByNid(
          certReqMsg->certReq->certTemplate->extensions,
          NID_subjectAltName, 0 /* non-critical */,
          ASN(certHolder->getSubAltName())) == SUCCESS);
      }
    }
    else
    {
      ASN_Del(subjectAltName);
    }
  }

  // 1.3. controls�� ����
  if (certReqMsg->certReq->controls != NULL)
  {
    int i;
    for (i = 0; i < certReqMsg->certReq->controls->size; i++)
    {
      /* 1.2.1. pkiArchiveOptions */
      if (certReqMsg->certReq->controls->member[i]->type->nid == NID_pkiArchiveOptions)
      {
        PKIArchiveOptions *pkiArchiveOpts;
        ASNBuf *pkiArchiveOptsBuf;
        ret = ::ASNAny_Get(
          &pkiArchiveOptsBuf, certReqMsg->certReq->controls->member[i]->value);
        if (ret < 0)
        {
          /*# Exception : �߸��� pkiArchiveOptions �� */
          /*# LOG : pkiArchiveOptions �ؼ� ���� */
          CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_RESOLVE_PKIARCHIVEOPTS_N);
          e.addOpts(
            "�ش� certReqMsg�� index(0����) : %i, �ش� pkiArchivalOptions(DER Encoded) : %a",
            ctx.reqIndex,
            certReqMsg->certReq->controls->member[i]->value);
          throw e;
        }
        pkiArchiveOpts = ASN_New(PKIArchiveOptions, pkiArchiveOptsBuf);
        ASNBuf_Del(pkiArchiveOptsBuf);
        if (pkiArchiveOpts == NULL)
        {
          /*# Exception : �߸��� pkiArchiveOptions �� */
          /*# LOG : pkiArchiveOptions �ؼ� ���� */
          CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_RESOLVE_PKIARCHIVEOPTS_N);
          e.addOpts(
            "�ش� certReqMsg�� index(0����) : %i, �ش� pkiArchivalOptions(DER Encoded) : %a",
            ctx.reqIndex,
            certReqMsg->certReq->controls->member[i]->value);
          throw e;
        }
        // pkiArchiveOptions�� ��ĪŰ ��ȣȭ �Ǿ� �ִ� ��쿣 CA ����Ű�� ��ȣȭ �Ǿ� �ִ� ������ ��ü */
        if (pkiArchiveOpts->select == PKIArchiveOptions_encryptedPrivKey &&
            pkiArchiveOpts->choice.encryptedPrivKey->select == CRMFEncryptedKey_encryptedValue &&
            pkiArchiveOpts->choice.encryptedPrivKey->choice.encryptedValue->encSymmKey == NULL)
        {
          AlgorithmIdentifier *hashAlg = ASN_New(AlgorithmIdentifier, NULL);
          AlgorithmIdentifier *symmAlg = reinterpret_cast<AlgorithmIdentifier*>(
            ::ASN_Dup(ASN(pkiArchiveOpts->choice.encryptedPrivKey->choice.encryptedValue->symmAlg)));
          // ���� ���� ����
          VERIFY(::ASNChoice_Select(
            ASN_CHOICE(pkiArchiveOpts->choice.encryptedPrivKey), 0) == SUCCESS);
          // ���ο� ���� ����
          VERIFY(::ASNChoice_Select(
            ASN_CHOICE(pkiArchiveOpts->choice.encryptedPrivKey),
            CRMFEncryptedKey_encryptedValue) == SUCCESS);
          VERIFY(reqCertInfo->privateKey); // privateKey�� �����ؾ� ��
          ASNBuf *pPriKeyInfoBuf = ::ASN_EncodeDER(reqCertInfo->privateKey);

          VERIFY(::AlgorithmIdentifier_SetNid(
            hashAlg, NID_SHA1, NULL) == SUCCESS);
          VERIFY(::EncryptedValue_Set(
            pkiArchiveOpts->choice.encryptedPrivKey->choice.encryptedValue,
            reinterpret_cast<unsigned char*>(pPriKeyInfoBuf->data),
            pPriKeyInfoBuf->len,
            NULL, DEFAULT_SYMMETRIC_KEY_LEN,
            symmAlg,
            AuthorityLoginProfile::get()->getCACerts().begin()->get()->
              tbsCertificate->subjectPublicKeyInfo,
            hashAlg) == SUCCESS);
          ASN_Del(hashAlg);
          ASN_Del(symmAlg);
          ASNBuf_Del(pPriKeyInfoBuf);

          VERIFY(::ASNSeqOf_Remove(
            ASN_SEQOF(certReqMsg->certReq->controls), i) == SUCCESS);
          VERIFY(::SeqOfAttributeTypeAndValue_Add(
            certReqMsg->certReq->controls,
            NID_pkiArchiveOptions,
            ASN(pkiArchiveOpts)) == SUCCESS);
        }
        else
        {
          ASN_Del(pkiArchiveOpts);
        }
      }
    }
  }

  // 1.3.1. ���� KeyPolicyId�� Control�� ������� ���� ���, �߰����ش�.
  bool addKeyPolicyId = true;
  if (certReqMsg->certReq->controls != NULL)
  {
    int i;
    for (i = 0; i < certReqMsg->certReq->controls->size ; i++)
    {
      if (certReqMsg->certReq->controls->member[i]->type->nid ==
        NID_penta_at_cmp_keyPolicyId)
      {
        addKeyPolicyId = false;
        break;
      }
    }
  }
  else
  {
    VERIFY(::ASNSeq_NewOptional(
      pASN(&certReqMsg->certReq->controls), ASN_SEQ(certReqMsg->certReq)) == SUCCESS);
  }

  if (addKeyPolicyId)
  {
    OctetString *pKeyPolicyId = ASN_New(OctetString, NULL);
    VERIFY(::ASNOctStr_Set(
      pKeyPolicyId, policy->sid.c_str(), policy->sid.size()) != FAIL);
    VERIFY(::SeqOfAttributeTypeAndValue_Add(
      reinterpret_cast<SeqOfAttributeTypeAndValue*>(certReqMsg->certReq->controls),
      NID_penta_at_cmp_keyPolicyId, ASN(pKeyPolicyId)) == SUCCESS);
    ASN_Del(pKeyPolicyId);
  }

  // 2. POP �� ����
  VERIFY(::ASNSeq_NewOptional(
    pASN(&newReqCertInfo->popTechnique), ASN_SEQ(newReqCertInfo.get())) == SUCCESS);
  int popTech;
  VERIFY(::ASNInt_GetInt(&popTech, reqCertInfo->popTechnique) == SUCCESS);
  if (popTech == POP_Technique_EKPOPThisMessage)
  {
    // POP_Technique_EKPOPThisMessage ����� ��쿡��
    // RFC������ CA ����Ű�� ������� �����Ű�� ��ȣȭ �ϵ��� �Ǿ�������
    // (��õǾ� ������ ������, ���� �������� �ؼ���...)
    // �� CA/RA������ �پ��� ����� �����ϱ� ����
    // ir, ccr �޽����� ��쿡�� ����� �����ÿ� ���� secret value�ε�
    // ��ȣȭ �� �� �ְ� �Ǿ� �����Ƿ�, �� ��쿡��
    // RA���� �ٽ� CA ����Ű�� ��ȣȭ �Ͽ� POP�� �缳�� �Ѵ�.
    // (POP�� POP_Technique_RAVerified�� ������ ���� ������,
    //  �� �����Ű ���� CA���� ������ �������� ���Ǵ� ��찡 �����Ƿ�,
    //  ��ȣȭ �Ͽ� ������ ������ �����Ͽ���)
    if (reqCertInfo->privateKey != NULL)
    {
      // RA���� ��ȣȭ �Ͽ� �����Ű�� �̹� ������ �ִ� ���

      // ���� ���� ����
      VERIFY(::ASNChoice_Select(ASN_CHOICE(certReqMsg->pop), 0) == SUCCESS);
      // ���ο� �� ����
      AlgorithmIdentifier *symmAlg = ASN_New(AlgorithmIdentifier, NULL);
      VERIFY(::AlgorithmIdentifier_SetNid(
        symmAlg, AuthorityLoginProfile::get()->getDefaultSymmAlgNid(), NULL) == SUCCESS);
      ret = ::CMP_MakePOP(
        certReqMsg->pop,
        certReqMsg->certReq,
        NULL,
        reqCertInfo,
        AuthorityLoginProfile::get()->getCACerts().begin()->get(),
        symmAlg);
      ASN_Del(symmAlg);

      if (ret != SUCCESS)
        /*# Exception : POP ���� ���� */
        throw CMPSendErrorException(LOG_CAMSGD_FAIL_TO_MAKE_POP_FOR_CA_N);
    }

    VERIFY(::ASNInt_SetInt(
      newReqCertInfo->popTechnique, POP_Technique_EKPOPThisMessage) == SUCCESS);
  }
  // �������������� PKCS10 ��û�� ���� �� �ְ� �ϱ� ���ؼ�
  // raVerified�� ��� ��Ŵ
  else if (popTech == POP_Technique_SKPOP ||
    popTech == POP_Technique_EKPOPEncryptedCert ||
    popTech == POP_Technique_RAVerified)
  {
    VERIFY(::ASNChoice_Select(
      ASN_CHOICE(certReqMsg->pop), ProofOfPossession_raVerified) == SUCCESS);
    VERIFY(::ASNInt_SetInt(
      newReqCertInfo->popTechnique, POP_Technique_RAVerified) == SUCCESS);
  }
  else
    // not supported (CMP_VerifyPOP �Լ� ����)
    VERIFY(false);

  ASN_Copy(newReqCertInfo->archiveKey, reqCertInfo->archiveKey);
  ASN_Copy(newReqCertInfo->sigOrEncKeyAlg, reqCertInfo->sigOrEncKeyAlg);
  ASN_Copy(newReqCertInfo->keyLen, reqCertInfo->keyLen);

  ctx.certReqMsgToCA = certReqMsg;
  ctx.reqCertInfoToCA = newReqCertInfo;
}

void CMP::requestCertsToCA()
{
  // 1. CA�� ��û �޽����� �����ϰ� ���� �޽����� ����
  sendAndRecvMessageWithCA();

  // 2. CA�κ��� ���� ���� �޽����� �ؼ��Ͽ� �߱޵� �������� ����
  boost::shared_ptr<PKIRepInfo> repInfo(
    ASN_New(PKIRepInfo, NULL), ASN_Delete);

  if (::PKIMSG_ResolveResponse(
    repInfo.get(), _reqContextToCA.get(), _resMessageFromCA.get(), 0) != SUCCESS)
    /*# Exception : CA�κ����� ���� �޽��� �ؼ� ���� */
    /*# LOG : CA�κ��� �ؼ��� �� ���� �޽��� ���� */
    /*# FIXME : �޽����� �α׷� ����� �� ����ϱ� */
    throw CMPSendErrorException(LOG_CAMSGD_INVALID_MESSAGE_FROM_CA_N);

  switch (repInfo->select)
  {
  case PKIRepInfo_certResponse:
    {
    DBSubject *sender = dynamic_cast<DBSubject *>(_sender.get());

    DBEntity *entity;
    DBAuthority *authority;

    int status;
    int resIdx;
    for (resIdx=0; resIdx < repInfo->choice.certResponse->response->size;
      resIdx++)
    {
      ISSUE_CONTEXT &ctx = _issueCtxToCA[resIdx];

      DBSubject *certHolder = dynamic_cast<DBSubject *>(ctx.certHolder.get());
      DBPolicy *policy = dynamic_cast<DBPolicy *>(ctx.policy.get());

      try
      {
        VERIFY(::ASNInt_GetInt(
          &status,
          repInfo->choice.certResponse->response->member[resIdx]->status->status) != FAIL);
        if (status == PKIStatus_accepted || status == PKIStatus_grantedWithMods)
        {
          // CA���� �������� �߱޵� ���
          // ������ ����
          if ((entity = dynamic_cast<DBEntity*>(certHolder)) != NULL)
          {
            DBEntityPKC *entityPKC =
              new DBEntityPKC(
                repInfo->choice.certResponse->response->member[resIdx]->certificate);
            entityPKC->esid = certHolder->getSID();
            entityPKC->csid = sender->getSID();
            entityPKC->stat = PKIDB_PKC_STAT_HOLD; // conf ���� ���ο� ���� GOOD/REVOKE ����
            entityPKC->psid = policy->sid;

            try
            {
              entityPKC->insert();
            }
            catch (DBCommandException)
            {
              delete entityPKC;
              /*# ERROR : �߱޵� �������� DB�� �����ϴµ� ����(systemFailure(draft)) */
              /*# LOG : ������ �������� DB�� �����ϴµ� ���� */
              CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_INSERT_CERT_TO_DB_N);
              e.addOpt("�ش� certReqMsg�� index(0����)", ctx.reqIndex);
              throw e;
            }
            ctx.pkc.reset(entityPKC);
          }
          else
          {
            authority =
              boost::polymorphic_downcast<DBAuthority *>(certHolder);

            DBAuthorityPKC *authorityPKC =
              new DBAuthorityPKC(
                repInfo->choice.certResponse->response->member[resIdx]->certificate);
            authorityPKC->asid = certHolder->getSID();
            authorityPKC->stat = PKIDB_PKC_STAT_HOLD;

            try
            {
              authorityPKC->insert();
            }
            catch (DBCommandException)
            {
              delete authorityPKC;
              /*# ERROR : �߱޵� �������� DB�� �����ϴµ� ����(systemFailure(draft)) */
              /*# LOG : ������ �������� DB�� �����ϴµ� ���� */
              CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_INSERT_CERT_TO_DB_N);
              e.addOpt("�ش� certReqMsg�� index(0����)", ctx.reqIndex);
              throw e;
            }
            ctx.pkc.reset(authorityPKC);
          }
          // CA���� �����Ű�� �����ϴ� ��쿡 ���� ó��(not implemented)
        }
        else
        {
          // CA���� ������ �߱��� �źε� ���
          PKIStatusInfo *status =
            repInfo->choice.certResponse->response->member[resIdx]->status;
          std::ostringstream ost;
          ost << "�ش� certReqMsg�� index(0����) : " << ctx.reqIndex;

          if (status->statusString != NULL &&
            status->statusString->size > 0)
          {
            ost << ", CA�κ����� ���� �޽��� ���� statusString : ";
            ost << type2string<ASNUTF8Str *>(status->statusString->member[0]);
          }
          /*# LOG : CA�κ��� ������ �߱� �޴µ� ���� */
          CMPSendErrorException e(LOG_CAMSGD_CERT_ISSUE_REJECTED_BY_CA_N);
          e.addOpts(ost.str().c_str());
          throw e;
        }
      }
      catch (CMPException &e)
      {
        // log ���
        LogItemSharedPtr logItem(AuthorityLoginProfile::get()->getLog()->createLogItem());
        logItem->setLogItem(e.getCode(), e.getOpts().c_str());
        logItem->setRequester(getLogReqInfo(_sender, _sock.getPeerName()));
        //logItem->setWorker(DBObjectBase::getSelf());
        logItem->setCertHolder(getLogHolderInfo(_certHolder));
        logItem->write();

        // error response ����
        VERIFY(e.getErrorMsgContent());
        CertReqMessages *certReqMessages =
          _reqMessage->body->choice.ir; // union�̱� ������ ir, cr, ccr, kur�� ��� ����

        CertResponse *errorResponse = ASN_New(CertResponse, NULL);
        ASN_Copy(
          errorResponse->certReqId,
          certReqMessages->member[ctx.reqIndex]->certReq->certReqId);
        ASN_Copy(
          errorResponse->status,
          e.getErrorMsgContent()->pKIStatusInfo);

        ctx.certResponse.reset(errorResponse, ASN_Delete);
      }
    }
    break;
    }
  case PKIRepInfo_errorResponse:
    {
    /*# ERROR: Error Message ���� (systemFailure:CA ���� �޽��� ����) */
    /*# LOG : CA�κ��� Error �޽��� ���� */
    std::ostringstream ost;
    ErrorMsgContent *errorMsg = repInfo->choice.errorResponse;

    if (errorMsg->pKIStatusInfo->statusString != NULL &&
      errorMsg->pKIStatusInfo->statusString->size > 0)
    {
      ost << "statusString : ";
      ost << type2string<ASNUTF8Str *>(
              errorMsg->pKIStatusInfo->statusString->member[0]);
    }

    if (errorMsg->errorCode != NULL)
    {
      if (!ost.str().empty()) ost << ", ";
      ost << "errorCode : ";
      ost << errorMsg->errorCode;
      ost << ", ";
    }

    if ( errorMsg->errorDetails != NULL &&
      errorMsg->errorDetails->size > 0 )
    {
      if (!ost.str().empty()) ost << ", ";
      ost << "errorDetails : ";
      ost << type2string<ASNUTF8Str *>(errorMsg->errorDetails->member[0]);
    }

    CMPSendErrorException e(LOG_CAMSGD_ERROR_MESSAGE_FROM_CA_N);
    e.addOpts(ost.str().c_str());
    throw e;
    }
  default:
    VERIFY(false);
  }
}

}
