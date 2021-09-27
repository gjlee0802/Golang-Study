/**
 * @file    CMP_recvCertsFromCA.cpp
 *
 * @desc    인증서를 발급 혹은 CA로 발급 요청 대행을 하는 function의 RA specific 구현
 * @author   조현래(hrcho@pentasecurity.com)
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

      // error response 설정
      VERIFY(e.getErrorMsgContent());
      CertReqMessages *certReqMessages =
        _reqMessage.get()->body->choice.ir; // union이기 때문에 ir, cr, ccr, kur이 모두 동일
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

    // FIXME : 비효율적..(AddP를 하고 나중에 수동으로 지우는 방식 등을 고려해 볼 것)
    VERIFY(::ASNSeqOf_Add(
      ASN_SEQOF(reqBody->choice.ir), ASN(i->certReqMsgToCA.get())) == SUCCESS);
      // choice이므로 ir, kur, ccr, cr이 동일
  }

  if (reqBody->choice.ir->size == 0)
  {
    // 발급을 요청할 내용이 없는 경우
    return;
  }

  CnKSharedPtr raCnK(AuthorityLoginProfile::get()->getMyCnK());
  Certificate *caCert = AuthorityLoginProfile::get()->getCACerts().begin()->get();

  PKIMessage *reqMessage = ASN_New(PKIMessage, NULL);
  PKIContext *reqContext = ASN_New(PKIContext, NULL);
  PKISenderAuthInfo *reqAuthInfo = ASN_New(PKISenderAuthInfo, NULL);

  ::PKISenderAuthInfo_SetCertAndPriKey(
    reqAuthInfo,
    raCnK.first.get(), raCnK.second.get(), NULL, NID_SHA1); // Hash 알고리즘 고정
  // PKIContext 값을 수동으로 설정
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

  /*# FIXME : 비효율적..(PKIBody를 복사하지 않고 사용할 수 있도록 하는 것을 고려할 것) */
  ret = ::PKIMSG_MakePKIMessage(
    reqMessage, reqContext,
    0, reqAuthInfo, reqBody.get(), caCert);
  ASN_Del(reqAuthInfo);

  if (ret != SUCCESS)
  {
    ASN_Del(reqMessage);
    ASN_Del(reqContext);
    /*# Exception : 요청 메시지 생성 실패 */
    throw CMPSendErrorException(LOG_CAMSGD_FAIL_TO_MAKE_REQUEST_MESSAGE_N);
  }

  _reqMessageToCA.reset(reqMessage, ASN_Delete);
  _reqContextToCA.reset(reqContext, ASN_Delete);

  // FIXME : MacroCommand로 변경할 것
  requestCertsToCA();
}

void CMP::makeCertReq(ISSUE_CONTEXT &ctx)
{
  int ret;
  /**
   * RA에서 CA로 요청을 할 때에는 사용자의 요청 메시지에서 다음의 값들을 변경하여
   * 인증서 신청 메시지를 생성한다.
   *
   * 1. certReq 값
   * 1.1. certTemplate 값
   *    - certTemplate 내에 subject 값이 없는 경우, RA에서 추가한다.
   *    - certTemplate 내의 extension에 subjectAlternativeName을 추가
   * 1.2. controls 값
   *    - control 중에서 PKIArchiveOpt가 CA 공개키를 사용하여 생성되어 있는 경우에는
   *      그 값을 그대로 CA에게 전달하고, secretkey를 사용하여 생성되어 있는 경우에는
   *      그 값을 CA의 공개키로 암호화하여 새롭게 PKIArchiveOpt를 생성한다.
   *    - controls 값 내에 penta_at_cmp_keyPolicyId가 없는 경우에는
   *      새롭게 생성하여 추가한다.
   * 2. POP 값
   *  - POP가 비공개키를 CA의 공개키로 암호화하여 전달하여 이루어지는 경우를 제외하고는
   *    RA에서 POP검증이 이루어지므로 POP_Technique_RAVerified로 POP값을 수정.
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

  // 1. certTemplate 값 변경
  // 1.1. subject 값
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
      /*# Exception : 잘못된 DB 내 DN 값 */
      CMPSendErrorException e(LOG_CAMSGD_INVALID_SUBJECT_DN_IN_DB_N);
      e.addOpt("발급 대상 DN", certHolder->getDN());
      throw e;
    }
  }
  // 1.2. subjectAltName 값
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

  // 1.3. controls값 변경
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
          /*# Exception : 잘못된 pkiArchiveOptions 값 */
          /*# LOG : pkiArchiveOptions 해석 실패 */
          CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_RESOLVE_PKIARCHIVEOPTS_N);
          e.addOpts(
            "해당 certReqMsg의 index(0부터) : %i, 해당 pkiArchivalOptions(DER Encoded) : %a",
            ctx.reqIndex,
            certReqMsg->certReq->controls->member[i]->value);
          throw e;
        }
        pkiArchiveOpts = ASN_New(PKIArchiveOptions, pkiArchiveOptsBuf);
        ASNBuf_Del(pkiArchiveOptsBuf);
        if (pkiArchiveOpts == NULL)
        {
          /*# Exception : 잘못된 pkiArchiveOptions 값 */
          /*# LOG : pkiArchiveOptions 해석 실패 */
          CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_RESOLVE_PKIARCHIVEOPTS_N);
          e.addOpts(
            "해당 certReqMsg의 index(0부터) : %i, 해당 pkiArchivalOptions(DER Encoded) : %a",
            ctx.reqIndex,
            certReqMsg->certReq->controls->member[i]->value);
          throw e;
        }
        // pkiArchiveOptions이 대칭키 암호화 되어 있는 경우엔 CA 공개키로 암호화 되어 있는 값으로 대체 */
        if (pkiArchiveOpts->select == PKIArchiveOptions_encryptedPrivKey &&
            pkiArchiveOpts->choice.encryptedPrivKey->select == CRMFEncryptedKey_encryptedValue &&
            pkiArchiveOpts->choice.encryptedPrivKey->choice.encryptedValue->encSymmKey == NULL)
        {
          AlgorithmIdentifier *hashAlg = ASN_New(AlgorithmIdentifier, NULL);
          AlgorithmIdentifier *symmAlg = reinterpret_cast<AlgorithmIdentifier*>(
            ::ASN_Dup(ASN(pkiArchiveOpts->choice.encryptedPrivKey->choice.encryptedValue->symmAlg)));
          // 기존 값을 삭제
          VERIFY(::ASNChoice_Select(
            ASN_CHOICE(pkiArchiveOpts->choice.encryptedPrivKey), 0) == SUCCESS);
          // 새로운 값을 설정
          VERIFY(::ASNChoice_Select(
            ASN_CHOICE(pkiArchiveOpts->choice.encryptedPrivKey),
            CRMFEncryptedKey_encryptedValue) == SUCCESS);
          VERIFY(reqCertInfo->privateKey); // privateKey는 존재해야 함
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

  // 1.3.1. 만일 KeyPolicyId가 Control에 들어있지 않은 경우, 추가해준다.
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

  // 2. POP 값 변경
  VERIFY(::ASNSeq_NewOptional(
    pASN(&newReqCertInfo->popTechnique), ASN_SEQ(newReqCertInfo.get())) == SUCCESS);
  int popTech;
  VERIFY(::ASNInt_GetInt(&popTech, reqCertInfo->popTechnique) == SUCCESS);
  if (popTech == POP_Technique_EKPOPThisMessage)
  {
    // POP_Technique_EKPOPThisMessage 방식인 경우에는
    // RFC에서는 CA 공개키로 사용자의 비공개키를 암호화 하도록 되어있으나
    // (명시되어 있지는 않으나, 위의 내용으로 해석됨...)
    // 현 CA/RA에서는 다양한 방식을 지원하기 위해
    // ir, ccr 메시지인 경우에는 사용자 인증시에 사용된 secret value로도
    // 암호화 할 수 있게 되어 있으므로, 이 경우에는
    // RA에서 다시 CA 공개키로 암호화 하여 POP를 재설정 한다.
    // (POP를 POP_Technique_RAVerified로 수정할 수도 있으나,
    //  이 비공개키 값은 CA에서 저장을 목적으로 사용되는 경우가 있으므로,
    //  암호화 하여 보내는 쪽으로 구현하였음)
    if (reqCertInfo->privateKey != NULL)
    {
      // RA에서 복호화 하여 비공개키를 이미 가지고 있는 경우

      // 기존 값을 삭제
      VERIFY(::ASNChoice_Select(ASN_CHOICE(certReqMsg->pop), 0) == SUCCESS);
      // 새로운 값 설정
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
        /*# Exception : POP 생성 실패 */
        throw CMPSendErrorException(LOG_CAMSGD_FAIL_TO_MAKE_POP_FOR_CA_N);
    }

    VERIFY(::ASNInt_SetInt(
      newReqCertInfo->popTechnique, POP_Technique_EKPOPThisMessage) == SUCCESS);
  }
  // 관리도구에서도 PKCS10 요청을 보낼 수 있게 하기 위해서
  // raVerified도 통과 시킴
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
    // not supported (CMP_VerifyPOP 함수 참조)
    VERIFY(false);

  ASN_Copy(newReqCertInfo->archiveKey, reqCertInfo->archiveKey);
  ASN_Copy(newReqCertInfo->sigOrEncKeyAlg, reqCertInfo->sigOrEncKeyAlg);
  ASN_Copy(newReqCertInfo->keyLen, reqCertInfo->keyLen);

  ctx.certReqMsgToCA = certReqMsg;
  ctx.reqCertInfoToCA = newReqCertInfo;
}

void CMP::requestCertsToCA()
{
  // 1. CA로 요청 메시지를 전송하고 응답 메시지를 수신
  sendAndRecvMessageWithCA();

  // 2. CA로부터 받은 응답 메시지를 해석하여 발급된 인증서를 얻음
  boost::shared_ptr<PKIRepInfo> repInfo(
    ASN_New(PKIRepInfo, NULL), ASN_Delete);

  if (::PKIMSG_ResolveResponse(
    repInfo.get(), _reqContextToCA.get(), _resMessageFromCA.get(), 0) != SUCCESS)
    /*# Exception : CA로부터의 응답 메시지 해석 실패 */
    /*# LOG : CA로부터 해석할 수 없는 메시지 수신 */
    /*# FIXME : 메시지를 로그로 남기는 것 고려하기 */
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
          // CA에서 인증서가 발급된 경우
          // 인증서 저장
          if ((entity = dynamic_cast<DBEntity*>(certHolder)) != NULL)
          {
            DBEntityPKC *entityPKC =
              new DBEntityPKC(
                repInfo->choice.certResponse->response->member[resIdx]->certificate);
            entityPKC->esid = certHolder->getSID();
            entityPKC->csid = sender->getSID();
            entityPKC->stat = PKIDB_PKC_STAT_HOLD; // conf 수신 여부에 따라 GOOD/REVOKE 결정
            entityPKC->psid = policy->sid;

            try
            {
              entityPKC->insert();
            }
            catch (DBCommandException)
            {
              delete entityPKC;
              /*# ERROR : 발급된 인증서를 DB에 저장하는데 실패(systemFailure(draft)) */
              /*# LOG : 생성된 인증서를 DB에 저장하는데 실패 */
              CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_INSERT_CERT_TO_DB_N);
              e.addOpt("해당 certReqMsg의 index(0부터)", ctx.reqIndex);
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
              /*# ERROR : 발급된 인증서를 DB에 저장하는데 실패(systemFailure(draft)) */
              /*# LOG : 생성된 인증서를 DB에 저장하는데 실패 */
              CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_INSERT_CERT_TO_DB_N);
              e.addOpt("해당 certReqMsg의 index(0부터)", ctx.reqIndex);
              throw e;
            }
            ctx.pkc.reset(authorityPKC);
          }
          // CA에서 비공개키를 생성하는 경우에 대한 처리(not implemented)
        }
        else
        {
          // CA에서 인증서 발급이 거부된 경우
          PKIStatusInfo *status =
            repInfo->choice.certResponse->response->member[resIdx]->status;
          std::ostringstream ost;
          ost << "해당 certReqMsg의 index(0부터) : " << ctx.reqIndex;

          if (status->statusString != NULL &&
            status->statusString->size > 0)
          {
            ost << ", CA로부터의 응답 메시지 내의 statusString : ";
            ost << type2string<ASNUTF8Str *>(status->statusString->member[0]);
          }
          /*# LOG : CA로부터 인증서 발급 받는데 실패 */
          CMPSendErrorException e(LOG_CAMSGD_CERT_ISSUE_REJECTED_BY_CA_N);
          e.addOpts(ost.str().c_str());
          throw e;
        }
      }
      catch (CMPException &e)
      {
        // log 기록
        LogItemSharedPtr logItem(AuthorityLoginProfile::get()->getLog()->createLogItem());
        logItem->setLogItem(e.getCode(), e.getOpts().c_str());
        logItem->setRequester(getLogReqInfo(_sender, _sock.getPeerName()));
        //logItem->setWorker(DBObjectBase::getSelf());
        logItem->setCertHolder(getLogHolderInfo(_certHolder));
        logItem->write();

        // error response 설정
        VERIFY(e.getErrorMsgContent());
        CertReqMessages *certReqMessages =
          _reqMessage->body->choice.ir; // union이기 때문에 ir, cr, ccr, kur이 모두 동일

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
    /*# ERROR: Error Message 전송 (systemFailure:CA 에러 메시지 수신) */
    /*# LOG : CA로부터 Error 메시지 수신 */
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
