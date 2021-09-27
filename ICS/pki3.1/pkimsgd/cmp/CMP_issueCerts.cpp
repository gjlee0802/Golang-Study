/**
 * @file    CMP_issueCert_CA.hpp.cpp
 *
 * @desc    인증서를 발급 혹은 CA로 발급 요청 대행을 하는 function
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2002.05.01
 *
 * Revision History
 *
 * @date     2002.05.02 : Start
 *
 *
 */

// standard headers
#include <sstream>
#include <cassert>
#include <boost/cast.hpp>
#include <boost/scoped_array.hpp>

// cis headers
#include "pkimessage.h"
#include "rand_ansi.h"
#include "sha1.h"

#include "Trace.h"

// pki headers
#include "DBObject.hpp"
#include "DBSubject.hpp"
#include "DBPolicy.hpp"
#include "DBPKC.hpp"
#include "cis_cast.hpp"
#include "CMPSocket.hpp"
#include "Log.hpp"
#include "CnK_define.hpp"
#include "CertHelper.h"
#include "CertHelper.h"

#include "CALoginProfile.hpp"
#include "RALoginProfile.hpp"
#include "CMP.hpp"
#include "CMPException.hpp"
#include "PKILogTableDefine.hpp"

using namespace Issac::DB;
using namespace std;

#define TMPLOG "/tmp/cmp.log"

namespace Issac
{

/**
 *  인증서 발급 신청 메시지(ir, kur, cr, ccr) 처리 과정은 다음과 같다.
 *  1. CA의 경우
 *    1) 발급에 사용될 인증서 정책을 가져옴
 *    2) 인증서 신청 메시지가 올바른 형식을 가지고 있고, 정책에 부합하는지 확인
 *    3) 인증서 생성
 *    4) 생성된 인증서를 DB에 저장
 *    5) 응답 메시지 생성
 *  2. RA의 경우
 *    1) 발급에 사용될 인증서 정책을 가져옴
 *    2) 인증서 신청 메시지가 올바른 형식을 가지고 있고, 정책에 부합하는지 확인
 *    3) '2)'에서 검증된 요청에 대해서 CA에게 인증서 발급을 요청
 *      - 요청자로부터 수신한 요청 메시지를 수정하여 CA에게 보낼 요청 메시지를 생성
 *      - CA에게 요청 메시지 전달
 *      - CA로부터 응답 메시지 수신
 *    4) CA로부터 수신된 발급된 인증서들을 DB에 저장
 *      - 에러 메시지 수신 시, 해당 에러를 이용하여 응답 메시지 생성
 *    5) 응답 메시지 생성
 */

//////////////////////////////////////////////////////////////////////
// CMPIssueCertificate Class
//////////////////////////////////////////////////////////////////////

void CMP::issueCerts()
{
  // Memory 처리의 효율성을 높이기 위해 PKIMessage내의
  // CertReqMsg를 복사하지 않고 약간의 꽁수(?)를 사용.
  // 일반적으로는 ASN_Dup등을 사용하여 element를 복사한 뒤,
  // 새로 생성된 element를 context item으로 setting해야 하나
  // (복사를 하지 않으면 현 context의 구현상 2번 free하게 됨)
  // 여기에서는 PKIMessage내의 CertReqMessages의 size를 0으로 setting하여
  // PKIMessage로부터 context로 pointer의 소유권을 직접 이동시키는 방법을 사용하였다.

  CertReqMessages *certReqMessages = _reqMessage->body->choice.ir;
  int reqIdx;
  int reqCount = certReqMessages->size; // stores original size
  certReqMessages->size = 0;         // discards ownship of pointers

  // 1. 인증서 발급 이전에 요청 메시지 검사 & 해석
  for (reqIdx = 0; reqIdx < reqCount; ++reqIdx)
  {
    ISSUE_CONTEXT ctx;
    // FIXME - 아래의 코드는 stl 특성상 반복적 메모리 복사로 낭비가 심하다.
    // 하지만 중간에 오류가 나더라도 인덱스 수를 유지하기 위해서는
    // 마지막에 push_back을 하지 않고 미리 넣고 인덱싱했다.
    // 반드시 그래야 하는 것은 아니지만...
    _issueCtx.push_back(ctx);
    _issueCtx[reqIdx].certHolder = _certHolder;
    _issueCtx[reqIdx].reqIndex = reqIdx;
    _issueCtx[reqIdx].certReqMsg.reset(certReqMessages->member[reqIdx], ASN_Delete);
    _issueCtx[reqIdx].reqType = static_cast<int>(_reqMessage->body->select);

    try
    {
      // verify validity
      resolveCertReqMsg(_issueCtx[reqIdx]);
      getIssueInfo(_issueCtx[reqIdx]);
      checkPolicy(_issueCtx[reqIdx]);
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
      CertResponse *errorResponse = ASN_New(CertResponse, NULL);

      ASN_Copy(
        errorResponse->certReqId,
        certReqMessages->member[reqIdx]->certReq->certReqId);
      ASN_Copy(
        errorResponse->status,
        e.getErrorMsgContent()->pKIStatusInfo);

      _issueCtx[reqIdx].certResponse.reset(errorResponse, ASN_Delete);
    }
  }

  // 2. 인증서 발급
  if (CALoginProfile::get())
    makeCerts();
  else
    recvCertsFromCA();

  // 3. certResponse 생성
  makeCertResponse();

  // 4. 응답 메시지 body 생성
  _resBody.reset(ASN_New(PKIBody, NULL), ASN_Delete);

  switch (_reqMessage->body->select)
  {
  case PKIBody_ir :
    ASNChoice_Select(ASN_CHOICE(_resBody.get()), PKIBody_ip);
    break;
  case PKIBody_cr :
    ASNChoice_Select(ASN_CHOICE(_resBody.get()), PKIBody_cp);
    break;
  case PKIBody_kur :
    ASNChoice_Select(ASN_CHOICE(_resBody.get()), PKIBody_kup);
    break;
  case PKIBody_ccr :
    ASNChoice_Select(ASN_CHOICE(_resBody.get()), PKIBody_ccp);
    break;
  default :
    VERIFY(false);
  }

  // response의 caPubs 필드 설정
  /*# FIXME : CA의 NewWithOld, OldWithNew도 추가하는 것을 고려할 것 */
  /*# FIXME : 사용자가 최신 인증서를 가지고 있는지 판단하는 방법이 부적절함 */
  if (_recipCnK.first.get() !=
    AuthorityLoginProfile::get()->getMyCnK().first.get())
  {
    // 사용자가 기존의 CA 인증서를 가지고 있는 경우
    // union이기 때문에 ip, cp, ccp, kup가 모두 동일
    VERIFY(::ASNSeq_NewOptional(
      pASN(&_resBody->choice.ip->caPubs),
      ASN_SEQ(_resBody->choice.ip)) == SUCCESS);
    VERIFY(::ASNSeqOf_Add(
      ASN_SEQOF(_resBody->choice.ip->caPubs),
      ASN(AuthorityLoginProfile::get()->getCACerts().begin()->get())) == SUCCESS);
  }
  else if (_senderAuthInfo->select == PKISenderAuthInfo_secretValue)
  {
    // 사용자가 MAC protection을 사용하여 요청 메시지를 작성한 경우
    // union이기 때문에 ip, cp, ccp, kup가 모두 동일
    VERIFY(::ASNSeq_NewOptional(
      pASN(&_resBody->choice.ip->caPubs),
      ASN_SEQ(_resBody->choice.ip)) == SUCCESS);
    VERIFY(::ASNSeqOf_Add(
      ASN_SEQOF(_resBody->choice.ip->caPubs),
      ASN(AuthorityLoginProfile::get()->getCACerts().begin()->get())) == SUCCESS);
  }

  for (vector<ISSUE_CONTEXT>::iterator i = _issueCtx.begin();
     i != _issueCtx.end(); i++)
  {
    // union이기 때문에 ip, cp, ccp, kup가 모두 동일
    // memory copy 회수를 줄이기 위해 shared_ptr의 소유권을 강제적으로 해제할 수는 없나?
    // 단 conf 처리시에도 certResponse를 사용하므로 주의할 것
    VERIFY(::ASNSeqOf_Add(
      ASN_SEQOF(_resBody->choice.ip->response),
      ASN(i->certResponse.get())) == SUCCESS);
  }
}

void CMP::getIssueInfo(ISSUE_CONTEXT &ctx)
{
  // DB로부터 다음의 정보들을 가져온다.
  // 1. 인증서 발급에 필요한 인증서 정책
  // 2. 상호 인증 인증서 혹은 키 갱신을 하지 않는 인증서 갱신 시에
  //    주체 키 식별자가 같은 값으로 유지되도록 하기 위한 기존 인증서의 주체 키 식별자 값

  DBSubject *certHolder = dynamic_cast<DBSubject*>(ctx.certHolder.get());

  boost::shared_ptr<OctetString> policySid;
  boost::shared_ptr<OldCertId> oldCertId;

  if (ctx.certReqMsg->certReq->controls != NULL)
  {
    policySid.reset(
      Controls_GetByType(
        ctx.certReqMsg->certReq->controls,
        OctetString, NID_penta_at_cmp_keyPolicyId),
      ASN_Delete);
    oldCertId.reset(
      Controls_GetByType(
        ctx.certReqMsg->certReq->controls, OldCertId, NID_oldCertID),
      ASN_Delete);
  }

  if (policySid.get() != NULL)
  {
    // 요청 메시지 내에 SID가 지정되어 있는 경우, 해당 값으로 policy 값을 얻음
    // 해당 policy가 사용자에게 할당되어 있는지 확인
    char sid[64];
    VERIFY(::ASNOctStr_Get(
      sid, sizeof(sid), policySid.get()) != FAIL);
    ctx.policy = certHolder->getPolicy(sid);
  }
  else if (ctx.reqType == PKIBody_kur && oldCertId.get() != NULL)
  {
    // key update인 경우 메시지 안에 oldCertId가 있으면 그 값으로 policy값을 얻음
    DBEntity *entity;
    DBAuthority *authority;

    char serNum[100];

    std::ostringstream ost;
    VERIFY(::ASNInt_GetStr(
      serNum, sizeof(serNum), oldCertId->serialNumber) != FAIL);
    if ((entity = dynamic_cast<DBEntity*>(certHolder)) != NULL)
    {
      boost::shared_ptr<DBEntityPKC> pkc;
      ost <<
        "SER='" << serNum << "' AND " <<
        "ESID='" << entity->sid << "'";

      try
      {
        pkc = Issac::DB::selectEx<DBEntityPKC>(ost.str().c_str());
      }
      catch (DBSelectException)
      {
        // 잘못된 certId
        /*# LOG : 잘못된 oldCertId 값 */
        CMPSendErrorException e(LOG_CAMSGD_BAD_OLDCERTID_N);
        e.addOpts(
          "해당 certReqMsg의 index(0부터) : %i, oldCertId의 serialNumber 값 : %s",
          ctx.reqIndex, serNum);
        throw e;
      }

      // 인증서 발급 신청 내의 공개키가 기존의 인증서의 공개키와 같은 경우
      // 기존 인증서로부터 KID값을 가져옴
      boost::shared_ptr<Certificate> cert;
      try
      {
        cert = pkc->getCertificate();
        getPreviousKeyId(ctx.reqCertInfo.get(), cert.get());
      }
      catch (Exception) {} // ignored

      try
      {
        ctx.policy = certHolder->getPolicy(pkc->psid);
      }
      catch (DBSelectException)
      {
        // DB 데이터의 문제
        /*# LOG : 발급을 위한 사용자 정보 가져오기 실패 */
        CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_GET_SUBJECT_INFO_N);
        e.addOpt("발급 대상 DN", entity->dn);
        throw e;
      }
    }
    else
    {
      authority =
        boost::polymorphic_downcast<DBAuthority *>(certHolder);
      boost::shared_ptr<DBAuthorityPKC> pkc;
      ost <<
        "SER='" << serNum << "' AND " <<
        "ASID='" << authority->sid << "'";

      try
      {
        pkc = selectEx<DBAuthorityPKC>(ost.str().c_str());
      }
      catch (DBSelectException)
      {
        // 잘못된 certId
        /*# LOG : 잘못된 oldCertId 값 */
        CMPSendErrorException e(LOG_CAMSGD_BAD_OLDCERTID_N);
        e.addOpts(
          "해당 certReqMsg의 index(0부터) : %i, oldCertId의 serialNumber 값 : %s",
          ctx.reqIndex, serNum);
        throw e;
      }
      // 인증서 발급 신청 내의 공개키가 기존의 인증서의 공개키와 같은 경우
      // 기존 인증서로부터 KID값을 가져옴
      boost::shared_ptr<Certificate> cert;
      try
      {
        cert = pkc->getCertificate();
        getPreviousKeyId(ctx.reqCertInfo.get(), cert.get());
      }
      catch (Exception) {} // ignored

      try
      {
        ctx.policy = certHolder->getPolicy(authority->psid);
      }
      catch (DBSelectException)
      {
        // DB 데이터의 문제
        /*# LOG : 발급을 위한 사용자 정보 가져오기 실패 */
        CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_GET_SUBJECT_INFO_N);
        e.addOpt("발급 대상 DN", authority->dn);
        throw e;
      }
    }
  }
  else if (ctx.reqType == PKIBody_cr)
  {
    // cr의 경우에는 사용자에게 인증서가 발급되지 않은 policy들에 대해서 인증서 발급
    try
    {
      ctx.policy = certHolder->getUnusedPolicy(ctx.reqIndex);
    }
    catch (Exception)
    {
      // 사용자에게 인증서가 발급되지 않은 policy의 개수가 요청 개수보다 적음
      /*# LOG : 발급을 요청하는 인증서의 개수가 사용자에게 설정되어 있는 개수와 일치하지 않음 */
      /*# FIXME : 단순히 policy를 가져오는데 실패한 경우일 수도 있으므로 구분할 것...*/
      CMPSendErrorException e(LOG_CAMSGD_INCORRECT_NUM_OF_CERTREQ_N);
      e.addOpts(
        "PKIBody의 choice 값 : %i, 해당 certReqMsg의 index(0부터) : %i",
        ctx.reqType - 1, ctx.reqIndex);
      throw e;
    }
  }
  else
  {
    // 그 이외의 경우에는 사용자에게 mapping되어 있는 policy 순서대로 가져옴
    // FIXME : kur의 경우에는?
    try
    {
      ctx.policy = certHolder->getPolicy(ctx.reqIndex);
    }
    catch (DBSelectException)
    {
      // 사용자에게 인증서가 발급되지 않은 policy의 개수가 요청 개수보다 적음
      /*# LOG : 발급을 요청하는 인증서의 개수가 사용자에게 설정되어 있는 개수와 일치하지 않음 */
      /*# FIXME : 단순히 policy를 가져오는데 실패한 경우일 수도 있으므로 구분할 것...*/
      CMPSendErrorException e(LOG_CAMSGD_INCORRECT_NUM_OF_CERTREQ_N);
      e.addOpts(
        "PKIBody의 choice 값 : %i, 해당 certReqMsg의 index(0부터) : %i",
        ctx.reqType - 1, ctx.reqIndex);
      throw e;
    }
  }

  // 상호 인증 인증서 신청인 경우에 주체 키 식별자 가져오기
  if (ctx.reqType == PKIBody_ccr)
  {
    boost::shared_ptr<DBAuthorityPKC> pkc;
    std::ostringstream ost;

    DBAuthority *authority =
      boost::polymorphic_downcast<DBAuthority *>(certHolder);
    DBAuthority *ca =
      boost::polymorphic_downcast<DBAuthority *>(
        DBObjectBase::getCA().get());
    ost <<
      "ASID='" << authority->sid << "' AND " <<
      "(ISSUERDN IS NULL OR ISSUERDN='' OR ISSUERDN!='" << ca->sid << '\'' <<
      "ORDER BY CDATE DESC";
    try
    {
      pkc = Issac::DB::selectEx<DBAuthorityPKC>(ost.str().c_str());
    }
    catch (DBSelectException)
    {
      /*# Exception : 상호 인증 기관의 인증서가 없음 */
      /*# LOG : 인증서를 발급할 상호 인증기관의 인증서가 DB에 들어가 있지 않음 */
      CMPSendErrorException e(LOG_CAMSGD_NO_CROSSCA_CERT_N);
      e.addOpt("해당 certReqMsg의 index(0부터)", ctx.reqIndex);
      throw e;
    }

    boost::shared_ptr<Certificate> cert;
    try
    {
      cert = pkc->getCertificate();
      getPreviousKeyId(ctx.reqCertInfo.get(), cert.get());
    }
    catch (Exception) { } // ignored
  }
}

void CMP::getPreviousKeyId(PKIReqCertInfo *reqCertInfo, Certificate *prevCert)
{
  VERIFY(reqCertInfo && prevCert);

  if (reqCertInfo == NULL || prevCert == NULL) return;

  // 기존 인증서에 SubjectKeyIdentifier가 없음
  if (prevCert->tbsCertificate->extensions == NULL) return;

  // 1. 공개키 값이 같은지 비교
  boost::shared_ptr<ASNBuf> recvedPubKeyBuf(
      ASN_EncodeDER(reqCertInfo->publicKey),
      ASNBuf_Delete);
  boost::shared_ptr<ASNBuf> storedPubKeyBuf(
      ASN_EncodeDER(prevCert->tbsCertificate->subjectPublicKeyInfo),
      ASNBuf_Delete);

  if (recvedPubKeyBuf->len != storedPubKeyBuf->len ||
    recvedPubKeyBuf->len == 0 ||
    ::memcmp(recvedPubKeyBuf->data, storedPubKeyBuf->data, recvedPubKeyBuf->len) != 0)
    return;

  SubjectKeyIdentifier *keyid = Extensions_GetByType(
    NULL, prevCert->tbsCertificate->extensions,
    SubjectKeyIdentifier, NID_subjectKeyIdentifier);

  if (keyid != NULL)
    VERIFY(::ASNSeq_NewSetPOptional(
      pASN(&reqCertInfo->subjectKeyId), ASN_SEQ(reqCertInfo),
      ASN(keyid)) == SUCCESS);
}

void CMP::checkPolicy(ISSUE_CONTEXT &ctx)
{
  int ret;

  DBPolicy *policy = boost::polymorphic_downcast<DBPolicy *>(
    ctx.policy.get());

  // 1. 공개키 값 검사
  if (ctx.reqCertInfo->publicKey != NULL)
  {
    // 1.1. 공개키 알고리즘 검사
    if (ctx.reqCertInfo->publicKey->algorithm->algorithm->nid !=
      string2type<Nid>(policy->tpubalg))
    {
      /*# Exception : 잘못된 공개키 알고리즘 */
      CMPSendErrorException e(LOG_CAMSGD_WRONG_PUBLICKEY_ALG_N);
      e.addOpts(
        "해당 certReqMsg의 index(0부터) : %i, "
        "요청 메시지 내의 공개키 알고리즘의 OID : %o, "
        "정책 명 : %s",
        ctx.reqIndex,
        &ctx.reqCertInfo->publicKey->algorithm->algorithm->oid,
        policy->name.c_str());
      throw e;
    }

    // 1.2. 공개키 길이 검사
    int keyBitLen;
    ret = CERT_GetKeyBitLength(&keyBitLen, ctx.reqCertInfo->publicKey);
    if (ret != SUCCESS)
    {
      /*# Exception : 잘못된 공개키 길이 */
      CMPSendErrorException e(LOG_CAMSGD_WRONG_PUBLICKEY_LEN_N);
      e.addOpts(
        "해당 certReqMsg의 index(0부터) : %i, "
        "정책 명 : %s",
        ctx.reqIndex, policy->name.c_str());
      throw e;
    }

    if (keyBitLen != policy->tpublen)
    {
      /*# Exception : 잘못된 공개키 길이 */
      CMPSendErrorException e(LOG_CAMSGD_WRONG_PUBLICKEY_LEN_N);
      e.addOpts(
        "해당 certReqMsg의 index(0부터) : %i, "
        "요청 메시지 내의 공개키 길이 : %i, "
        "정책 명 : %s",
        ctx.reqIndex, keyBitLen, policy->name.c_str());
      throw e;
    }

    // 1.3. 도메인 파라메터 검사
    if (policy->pqg.len != 0)
    {
      ASNBuf domainParamBuf;
      ASNBuf_SetP(&domainParamBuf, policy->pqg.data, policy->pqg.len);
      boost::shared_ptr<Parameter> pDomainParam(ASN_New(Parameter, &domainParamBuf), ASN_Delete);
      if (pDomainParam.get() == NULL)
      {
        /*# ERROR : 잘못된 DB 내의 도메인 파라메터 값 */
        /*# LOG : DB내의 도메인 파라메터 값이 올바르지 않음 */
        CMPSendErrorException e(LOG_CAMSGD_INVALID_DOMAINPARAM_IN_DB_N);
        e.addOpts(
          "해당 certReqMsg의 index(0부터) : %i, 정책 명 : %s",
          ctx.reqIndex, policy->name.c_str());
        throw e;
      }

      if (ctx.reqCertInfo->publicKey->algorithm->parameters != NULL)
      {
        if (::Parameter_Compare(
          ctx.reqCertInfo->publicKey->algorithm->parameters,
          pDomainParam.get(),
          ctx.reqCertInfo->publicKey->algorithm->algorithm->nid) != SUCCESS)
        {
          /*# ERROR : 잘못된 도메인 파라메터 값 */
          /*# LOG : 공개키 알고리즘 내의 도메인 파라메터 값이 설정값과 일치하지 않음 */
          CMPSendErrorException e(LOG_CAMSGD_WRONG_DOMAINPARAM_N);
          e.addOpts(
            "해당 certReqMsg의 index(0부터) : %i, "
            "요청 메시지 내의 도메인 파라메터(DER Encoded) : %a, "
            "정책 명 : %s",
            ctx.reqIndex,
            ctx.reqCertInfo->publicKey->algorithm->parameters,
            policy->name.c_str());
          throw e;
        }
      }
      else
      {
        // 도메인 파라메터를 넣어 줌
        VERIFY(::ASNSeq_NewOptional(
          pASN(&ctx.reqCertInfo->publicKey->algorithm->parameters),
          ASN_SEQ(ctx.reqCertInfo->publicKey->algorithm)) == SUCCESS);
        ASN_Copy(
          ctx.reqCertInfo->publicKey->algorithm->parameters, pDomainParam.get());
      }
    }
  } // else : 키쌍을 CA에서 생성하는 경우

  // 2. 비공개키 저장 여부 검사
  if (!policy->krsid.empty())
  {
    if (ctx.reqCertInfo->publicKey != NULL &&
      ctx.reqCertInfo->privateKey == NULL)
    {
      /*# Exception : 비공개키를 저장해야 되는데 전달되지 않음 */
      CMPSendErrorException e(LOG_CAMSGD_MISSING_PRIVATEKEY_N);
      e.addOpt("해당 certReqMsg의 index(0부터)", ctx.reqIndex);
      throw e;
    }
  }
}

//////////////////////////////////////////////////////////////////////
// CMPResolveCertReqMsgCommand Class
//////////////////////////////////////////////////////////////////////
void CMP::resolveCertReqMsg(ISSUE_CONTEXT &ctx)
{
  // PKIReqCertInfo *reqCertInfo = ASN_New(PKIReqCertInfo, NULL);
  ctx.reqCertInfo.reset(ASN_New(PKIReqCertInfo, NULL), ASN_Delete);

  // 1. CertReqMsg내의 certReq의 certTemplate field 값들이 올바른지 검사
  checkCertTemplate(ctx);
  // 2. CertReqMsg의 pop 검사 & 해석
  verifyPOP(ctx);
  // 3. CertReqMsg내의 certReq의 controls field 값들이 올바른지 검사 & 해석
  checkControls(ctx);
}

void CMP::checkCertTemplate(ISSUE_CONTEXT &ctx)
{
  /* 1. certTemplate 내용 검사 */
  /*    1.1. version 검사 */
  int ver;
  if (ctx.certReqMsg->certReq->certTemplate->version != NULL)
  {
    int ret = ::ASNInt_GetInt(&ver, ctx.certReqMsg->certReq->certTemplate->version);
    if (ret != SUCCESS || ver < CERT_VER1 || CERT_VER2 > ver)
    {
      /*# Exception : 잘못된 certTemplate version */
      CMPSendErrorException e(LOG_CAMSGD_INVALID_CERTTEMPLATE_VERSION_N);
      e.addOpts(
        "해당 certReqMsg의 index(0부터) : %i, certTemplate의 version : %i",
        ctx.reqIndex, ver);
      throw e;
    }
  }

  /*    1.2. issuer 영역 검사 */
  if (ctx.certReqMsg->certReq->certTemplate->issuer != NULL)
  {
    if (::Name_Compare(
      ctx.certReqMsg->certReq->certTemplate->issuer,
      AuthorityLoginProfile::get()->getMyCnK().first->tbsCertificate->subject) != 0)
    {
      /*# Exception : 잘못된 certTemplate issuer */
      CMPSendErrorException e(LOG_CAMSGD_INVALID_CERTTEMPATE_ISSUER_N);
      e.addOpts(
        "해당 certReqMsg의 index(0부터) : %i, certTemplate의 issuer : %s",
        ctx.reqIndex,
        type2string<Name*>(ctx.certReqMsg->certReq->certTemplate->issuer).c_str());
      throw e;
    }
  }

  /*    1.3. signingAlg 영역 검사 */
  if (ctx.certReqMsg->certReq->certTemplate->signingAlg != NULL)
  {
    /*# FIXME : hash 알고리즘은 SHA1으로 고정. */
    if (::AlgNid_GetSigAlgNid(
      AuthorityLoginProfile::get()->getMyCnK().first->tbsCertificate->
      subjectPublicKeyInfo->algorithm->algorithm->nid, NID_SHA1) !=
      ctx.certReqMsg->certReq->certTemplate->signingAlg->algorithm->nid)
    {
      /*# Exception : 잘못된 certTemplate signingAlg */
      CMPSendErrorException e(LOG_CAMSGD_INVALID_CERTTEMPLATE_SIGNALG_N);
      e.addOpts(
        "해당 certReqMsg의 index(0부터) : %i, certTemplate의 signingAlg OID : %o",
        ctx.reqIndex,
        &ctx.certReqMsg->certReq->certTemplate->signingAlg->algorithm->oid);
      throw e;
    }
  }

  /*    1.4. subject 영역 검사(subject에 대한 정보를 가져올 때 검사가 이루어지므로 생략) */
  /*    1.5. publicKey 영역 검사(POP확인 시 publicKey 검사도 이루어지므로 생략), */
  /*    1.6. 그외(serialNumber, issuerUID, subjectUID, validity값은 CA가 지정) */
}

void CMP::verifyPOP(ISSUE_CONTEXT &ctx)
{
  DBSubject *sender = dynamic_cast<DBSubject *>(
    _sender.get());

  if (ctx.certReqMsg->certReq->certTemplate->publicKey == NULL &&
    ctx.certReqMsg->pop == NULL)
  {
    /* 키쌍을 CA에서 생성하는 경우 */
  }
  else
  {
    PrivateKeyInfo *caPrivateKey, *oldCAPrivateKey;

    // POP 검증시 CA의 공개키로 사용자의 비공개키를 암호화 하여 전달하는 경우,
    // CA의 공개키가 갱신된 경우에는 현 공개키와 기존의 공개키 중 어떠한
    // 것으로 암호화 하여 전달되었는지를 판단할 수가 없기 때문에,
    // 이 경우에는 각각의 공개키에 대응되는 비공개키로 POP 검증을 수행해 본다.
    if (CALoginProfile::get())
    {
      CnKSharedPtrs cnKs(AuthorityLoginProfile::get()->getMyCnKs());
      CnKSharedPtrs::iterator i(cnKs.begin());
      caPrivateKey = i->second.get();
      ++i;
      oldCAPrivateKey =
        (i != cnKs.end()) ? i->second.get() : NULL;
    }
    else
      caPrivateKey = oldCAPrivateKey = NULL;

    char secretValue[MAX_SECRETVAL_LEN];
    int popTech;
    PublicKeyInfo *pubKey;
    PrivateKeyInfo *priKey;
    int ret;
    switch (_senderAuthInfo->select)
    {
    case PKISenderAuthInfo_secretValue :
      ret = ::CMP_VerifyPOP(
        &popTech, &pubKey, &priKey,
        ctx.certReqMsg.get(), caPrivateKey, NULL,
        secretValue);
      if (ret == ER_CMP_POP_FAIL_TO_DECRYPT &&
        oldCAPrivateKey != NULL)
        ret = ::CMP_VerifyPOP(
          &popTech, &pubKey, &priKey,
          ctx.certReqMsg.get(), caPrivateKey, NULL,
          secretValue);
      break;
    case PKISenderAuthInfo_certAndPriKey:
      ret = ::CMP_VerifyPOP(
        &popTech, &pubKey, &priKey,
        ctx.certReqMsg.get(), caPrivateKey, NULL,
        NULL);
      if (ret == ER_CMP_POP_FAIL_TO_DECRYPT &&
        oldCAPrivateKey != NULL)
        ret = ::CMP_VerifyPOP(
          &popTech, &pubKey, &priKey,
          ctx.certReqMsg.get(), caPrivateKey, NULL,
          NULL);
      break;
    default:
      VERIFY(false);
    }

    if (ret != SUCCESS && ret != ER_CMP_POP_CAPRIKEY_NOT_SUPPLIED)
    {
      /*# EXCEPTION : POP 검증 실패 */
      /*# LOG : 비공개키의 POP(Proof of possesion) 검증 실패 */
      CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_VERIFY_POP_N);
      e.addOpts(
        "해당 certReqMsg의 index(0부터) : %i, certReqMsg(DER Encoded) : %a",
        ctx.reqIndex, ctx.certReqMsg.get());
      throw e;
    }
    // POP 방식 검사
    if (popTech == POP_Technique_RAVerified)
    {
      // sender가 ADMIN || RA 일 때도 raVerified 통과
      if (::strcmp(sender->getType().c_str(), PKIDB_ENTITY_TYPE_RA) != 0 &&
          ::strcmp(sender->getType().c_str(), PKIDB_ENTITY_TYPE_ADMIN) != 0)
      {
        /*# Exception : 허가되지 않은 POP 방식(RAVerified) */
        /*# LOG : 허가되지 않은 POP 방식(RAVerified) */
        CMPSendErrorException e(LOG_CAMSGD_POP_RAVERIFIED_NOT_ALLOWED_N);
        e.addOpt("해당 ctx.certReqMsg의 index(0부터)", ctx.reqIndex);
        throw e;
      }
    }

    VERIFY(::ASNSeq_NewOptional(
      pASN(&ctx.reqCertInfo->popTechnique), ASN_SEQ(ctx.reqCertInfo.get())) == SUCCESS);
    VERIFY(::ASNInt_SetInt(
      ctx.reqCertInfo->popTechnique, popTech) == SUCCESS);
    VERIFY(::ASNSeq_NewSetPOptional(
      pASN(&ctx.reqCertInfo->publicKey),
      ASN_SEQ(ctx.reqCertInfo.get()), ASN(pubKey)) == SUCCESS);
    if (priKey != NULL)
      VERIFY(::ASNSeq_NewSetPOptional(
        pASN(&ctx.reqCertInfo->privateKey),
        ASN_SEQ(ctx.reqCertInfo.get()), ASN(priKey)) == SUCCESS);
  }
}

void CMP::checkControls(ISSUE_CONTEXT &ctx)
{
  /* 1. certReq의 controls값 해석 */
  if (ctx.certReqMsg->certReq->controls != NULL)
  {
    int i;
    for (i = 0; i < ctx.certReqMsg->certReq->controls->size; ++i)
    {
      /* 1.1. pkiArchiveOptions */
      if (ctx.certReqMsg->certReq->controls->member[i]->type->nid ==
        NID_pkiArchiveOptions)
      {
        /*# NOTE :  이미 privateKey 값을 얻은 경우는 pkiArchiveOptions를 무시 */
        if (ctx.reqCertInfo->privateKey != NULL) continue;

        ASNBuf *pkiArchiveOptsBuf;
        if (::ASNAny_Get(
          &pkiArchiveOptsBuf,
          ctx.certReqMsg->certReq->controls->member[i]->value) < 0)
        {
          /*# Exception : 잘못된 pkiArchiveOptions 값 */
          /*# LOG : pkiArchiveOptions 해석 실패 */
          CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_RESOLVE_PKIARCHIVEOPTS_N);
          e.addOpts(
            "해당 certReqMsg의 index(0부터) : %i, 해당 pkiArchivalOptions(DER Encoded) : %a",
            ctx.reqIndex,
            ctx.certReqMsg->certReq->controls->member[i]->value);
          throw e;
        }
        boost::shared_ptr<PKIArchiveOptions> pkiArchiveOpts(
          ASN_New(PKIArchiveOptions, pkiArchiveOptsBuf),
          ASN_Delete);
        ASNBuf_Del(pkiArchiveOptsBuf);
        if (pkiArchiveOpts.get() == NULL)
        {
          /*# Exception : 잘못된 pkiArchiveOptions 값 */
          /*# LOG : pkiArchiveOptions 해석 실패 */
          CMPSendErrorException e(
            LOG_CAMSGD_FAIL_TO_RESOLVE_PKIARCHIVEOPTS_N);
          e.addOpts(
            "해당 certReqMsg의 index(0부터) : %i, 해당 pkiArchivalOptions(DER Encoded) : %a",
            ctx.reqIndex,
            ctx.certReqMsg->certReq->controls->member[i]->value);
          throw e;
        }
        /*# NOTE : PKIArhicveOptions의 encryptedPrivKey를 사용하는 경우
         *         EncryptedValue와 EnvelopedData를 사용하는 2가지의 경우를 사용할 수 있으나,
         *         여기에서는 EncryptedValue를 이용하는 경우만 구현하고 있음.
         */
        if (pkiArchiveOpts->select != PKIArchiveOptions_encryptedPrivKey ||
          pkiArchiveOpts->choice.encryptedPrivKey->select != CRMFEncryptedKey_encryptedValue)
        {
          /*# Exception : 지원되지 않는 방식의 pkiArchiveOptions */
          /*# LOG : 지원되지 않는 방식의 pkiArhiveOptions */
          CMPSendErrorException e(
            LOG_CAMSGD_UNSUPPORTED_PKIARCHIVEOPTS_N);
          e.addOpts(
            "해당 certReqMsg의 index(0부터) : %i, 해당 pkiArchivalOptions(DER Encoded) : %a",
            ctx.reqIndex,
            ctx.certReqMsg->certReq->controls->member[i]->value);
          throw e;
        }

        int encryptedPriKeyLen =
          pkiArchiveOpts->choice.encryptedPrivKey->choice.encryptedValue->encValue->len;
        boost::scoped_array<unsigned char> encryptedPriKey(
          new unsigned char[encryptedPriKeyLen]);
        int ret;
        if (pkiArchiveOpts->choice.encryptedPrivKey->choice.encryptedValue->encSymmKey == NULL)
        {
          /* Secret Key 로 암호화 되어 있는 경우(Penta specific, RFC에는 기술되어 있지 않음) */
          char secretValue[MAX_SECRETVAL_LEN];
          if (_senderAuthInfo->select != PKISenderAuthInfo_secretValue)
          {
            /*# Exception : 잘못된 pkiArchiveOptions 값 */
            /*# LOG : pkiArchiveOptions 해석 실패 */
            CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_RESOLVE_PKIARCHIVEOPTS_N);
            e.addOpts(
              "해당 certReqMsg의 index(0부터) : %i, 해당 pkiArchivalOptions(DER Encoded) : %a",
              ctx.reqIndex,
              ctx.certReqMsg->certReq->controls->member[i]->value);
            throw e;
          }
          VERIFY(::ASNOctStr_Get(
            secretValue, sizeof(secretValue),
            _senderAuthInfo->choice.secretValue->secretValue) != FAIL);
          ret = ::EncryptedValue_Get(
            pkiArchiveOpts->choice.encryptedPrivKey->choice.encryptedValue,
            NULL,
            encryptedPriKey.get(), &encryptedPriKeyLen, encryptedPriKeyLen,
            reinterpret_cast<unsigned char *>(secretValue),
            NULL, ::strlen(secretValue),
            NULL);
        }
        else
        {
          if (CALoginProfile::get())
          {
            /* CA 공개키로 암호화 되어 있는 경우 */

            // CA의 공개키가 갱신된 경우에는 현 공개키와 기존의 공개키 중 어떠한
            // 것으로 암호화 하여 전달되었는지를 판단할 수가 없기 때문에,
            // 이 경우에는 각각의 공개키에 대응되는 비공개키로 복호화를 해본다.
            CnKSharedPtrs cnKs(AuthorityLoginProfile::get()->getMyCnKs());
            CnKSharedPtrs::iterator itr(cnKs.begin());
            PrivateKeyInfo *caPrivateKey = itr->second.get();
            ++itr;
            PrivateKeyInfo *oldCAPrivateKey =
              (itr != cnKs.end()) ? itr->second.get() : NULL;
            ret = ::EncryptedValue_Get(
              pkiArchiveOpts->choice.encryptedPrivKey->choice.encryptedValue,
              caPrivateKey,
              encryptedPriKey.get(), &encryptedPriKeyLen, encryptedPriKeyLen,
              NULL, NULL, 0, NULL);
            if (ret != SUCCESS)
            {
              ret = ::EncryptedValue_Get(
                pkiArchiveOpts->choice.encryptedPrivKey->choice.encryptedValue,
                oldCAPrivateKey,
                encryptedPriKey.get(), &encryptedPriKeyLen, encryptedPriKeyLen,
                NULL, NULL, 0, NULL);
            }
          }
          else
            continue;
        }
        if (ret != SUCCESS)
        {
          /*# Exception : 복호화 실패 */
          /*# LOG : PKIArchiveOptions 내의 비공개키 복호화 실패 */
          CMPSendErrorException e(
            LOG_CAMSGD_FAIL_TO_DECRYPT_PRIKEY_IN_ARCHIVEOPT_N);
          e.addOpts(
            "해당 certReqMsg의 index(0부터) : %i, 해당 pkiArchivalOptions(DER Encoded) : %a",
            ctx.reqIndex,
            ctx.certReqMsg->certReq->controls->member[i]->value);
          throw e;
        }

        ASNBuf priKeyBuf;
        ASNBuf_SetP(
          &priKeyBuf,
          reinterpret_cast<char *>(encryptedPriKey.get()), encryptedPriKeyLen);
        PrivateKeyInfo *priKey = ASN_New(PrivateKeyInfo, &priKeyBuf);
        if (priKey == NULL)
        {
          /*# Exception : 복호화 실패 */
          /*# LOG : PKIArchiveOptions 내의 비공개키 복호화 실패 */
          CMPSendErrorException e(
            LOG_CAMSGD_FAIL_TO_DECRYPT_PRIKEY_IN_ARCHIVEOPT_N);
          e.addOpts(
            "해당 certReqMsg의 index(0부터) : %i, 해당 pkiArchivalOptions(DER Encoded) : %a",
            ctx.reqIndex,
            ctx.certReqMsg->certReq->controls->member[i]->value);
          throw e;
        }

        VERIFY(::ASNSeq_NewSetPOptional(
          pASN(&ctx.reqCertInfo->privateKey), ASN_SEQ(ctx.reqCertInfo.get()),
          ASN(priKey)) == SUCCESS);
      }
    } /* for (i=0; i< certReqMsg->certReq->controls->size; i++) */
  }  /* if (certReqMsg->certReq->controls != NULL) */
}

void CMP::makeCerts()
{
  for (vector<ISSUE_CONTEXT>::iterator i = _issueCtx.begin();
    i != _issueCtx.end(); i++)
  {
    if (i->certResponse.get())
      continue;
    // 위에서 계속 패스하면 _revocable이 false이고
    // 따라서 나중에 실패해도 revoke할 필요없다.

    try
    {
      makeOneCert(*i);
      // 이곳을 지나야 비로서 revocable하다.
      _revocable = true;
    }
    catch (CMPException &e)
    {
      // error response 설정
      VERIFY(e.getErrorMsgContent());
      i->certResponse.reset(ASN_New(CertResponse, NULL), ASN_Delete);
      ASN_Copy(
        i->certResponse->certReqId, i->certReqMsg->certReq->certReqId);
      ASN_Copy(
        i->certResponse->status, e.getErrorMsgContent()->pKIStatusInfo);
    }
  }
}

static void SetEncryptedPrivateKey(
  PKIEntityPKC *pkc,
  DBPolicy *policy, PrivateKeyInfo *priKey)
{
  Certificate *certs[2] = { NULL, NULL };
  Parameter *domainParams[2] = { NULL, NULL };
  AlgDesc hashAlgs[2] = { SHA1, SHA1 };
  int certNum = 1;

  VERIFY(pkc && policy && priKey);

  // ca 인증서 정보 설정
  certs[0] = AuthorityLoginProfile::get()->getCACerts().begin()->get();

  // 키 복구 기관이 설정되어 있으면 키 복구 기관 인증서 읽어오기
  PKIEntityPKC krPKC;
  if (!policy->krsid.empty() && policy->krsid != CA_SELF_AUTHORITY_SID)
  {
    std::ostringstream ost;
    ost <<
      "ESID='" << policy->krsid << "' AND STAT='" << PKIDB_PKC_STAT_GOOD << "' "
      "ORDER BY CDATE DESC";
    PKIDBSel *select = ::PKI_DB_SelectRow(
      PKIENTITYPKC, &krPKC, DBConnection::getConn(), NULL,
      ost.str().c_str(), NULL);
    if (select != NULL)
    {
      ::PKI_DB_SelectClose(select);

      ASNBuf asnBuf;
      ASNBuf_SetP(&asnBuf, krPKC.pkc.data, krPKC.pkc.len);
      certs[1] = ASN_New(Certificate, &asnBuf);
      if (certs[1] != NULL) ++certNum;
    }
  }

  // ContentInfo 값 설정
  ContentInfo *contentInfo = ASN_New(ContentInfo, NULL);
  VERIFY(::ASNOid_SetByNid(contentInfo->contentType, NID_data) == SUCCESS);
  VERIFY(::ASNSeq_NewOptional(
    pASN(&contentInfo->content), ASN_SEQ(contentInfo)) == SUCCESS);
  VERIFY(::ASNAny_SetASN(contentInfo->content, ASN(priKey)) == SUCCESS);

  // EnvelopedData 생성
  EnvelopedData *envPriKey;
  int ret = ::EnvelopedData_Gen(
    &envPriKey,
    contentInfo,
    AuthorityLoginProfile::get()->getDefaultSymmAlgNid(),
    certNum, certs, domainParams, hashAlgs);
  ASN_Del(contentInfo);
  if (certs[1] != NULL) ASN_Del(certs[1]);
  if (ret != SUCCESS) return;

  ASNBuf *envPriKeyBuf = ::ASN_EncodeDER(envPriKey);
  VERIFY(envPriKeyBuf != NULL);
  ASN_Del(envPriKey);

  // pkc에 setting
  ::memcpy(pkc->ekey.data, envPriKeyBuf->data, envPriKeyBuf->len);
  pkc->ekey.len = envPriKeyBuf->len;
  ASNBuf_Del(envPriKeyBuf);

  if (certNum == 2) pkc->krcert = krPKC.ser;
  else
  {
    char buf[4096];
    VERIFY(::ASNInt_GetStr(
      buf, sizeof(buf),
      certs[0]->tbsCertificate->serialNumber) != FAIL);
    pkc->krcert = buf;
  }
}

int CMP::getPCRL_UnitCerts()
{
  static int unit = atoi(LoginProfile::get()->
    getProfile("CRL", "UNIT_CERTS").c_str());
  return unit;
}

bool CMP::isPCRL()
{
  static bool mod = LoginProfile::get()->
    getProfile("CRL", "TYPE") == "partitioned";
  int unit = getPCRL_UnitCerts();
  return mod && unit;
}

std::string CMP::getPCRL_CdpUriFormat()
{
  static string uri = LoginProfile::get()->getProfile("CRL",
      "CDP_URI_FORMAT");
  return uri;
}

int CMP::getPCRL_CurrentCertsCount()
{
  string count = AuthorityLoginProfile::get()->getDP()->get(
      PKIDB_GLOBAL_CERT_SECTION, PKIDB_GLOBAL_CERT_COUNT);
  return atoi(count.c_str());
}

std::string CMP::getPCRL_CdpUri(int certCount)
{
  if (isPCRL())
  {
    string fmtUri = LoginProfile::get()->getProfile("CRL", "CDP_URI_FORMAT");

    if (!fmtUri.empty())
    {
      char uri[2048];
      sprintf(uri, fmtUri.c_str(), certCount / getPCRL_UnitCerts());
      return uri;
    }
  }
  return "";
}

void CMP::makeOneCert(ISSUE_CONTEXT &ctx)
{
  int ret;
  CnKSharedPtr caCnK(AuthorityLoginProfile::get()->getMyCnK());

  DBSubject *sender = dynamic_cast<DBSubject *>(_sender.get());
  // sender는 하나다!
  DBSubject *certHolder = dynamic_cast<DBSubject *>(ctx.certHolder.get());
  DBPolicy *policy = boost::polymorphic_downcast<DBPolicy*>(ctx.policy.get());
  PKIReqCertInfo *reqCertInfo = ctx.reqCertInfo.get();
  int reqIdx = ctx.reqIndex;

  boost::shared_ptr<Certificate> newCert(
    ASN_New(Certificate, NULL), ASN_Delete);
  /*# FIXME : 더이상 PKIEntityInfo, PKIIssuerInfo, PKIPolicyInfo를 쓸 필요가 없으므로
   *          다른 방법으로 인증서 생성하는 것을 고려할 것
   */
  PKIEntityInfo *entityInfo = ASN_New(PKIEntityInfo, NULL);
  PKIPolicyInfo *policyInfo = ASN_New(PKIPolicyInfo, NULL);
  PKIIssuerInfo *issuerInfo = ASN_New(PKIIssuerInfo, NULL);

  VERIFY(::PKIEntityInfo_SetByStr(
    entityInfo, certHolder->getDN().c_str(), NULL, 0) == SUCCESS);
  if (certHolder->getSubAltName() != NULL)
    VERIFY(::ASNSeq_NewSetOptional(
      pASN(&entityInfo->subAltName), ASN_SEQ(entityInfo),
      ASN(certHolder->getSubAltName())) == SUCCESS);
  DBEntity *entity = dynamic_cast<DBEntity*>(certHolder);
  if (entity != NULL && entity->vlimit != 0)
  {
    struct tm notAfter;
    VERIFY(::ASNSeq_NewOptional(
      pASN(&entityInfo->notAfter), ASN_SEQ(entityInfo)) == SUCCESS);
    notAfter = *gmtime(&entity->vlimit);
    Time_Set(entityInfo->notAfter, &notAfter);
  }

  ASNBuf extensionsBuf;
  ASNBuf_SetP(&extensionsBuf, policy->plcder.data, policy->plcder.len);
  Extensions *extensions = ASN_New(Extensions, &extensionsBuf);
  VERIFY(::PKIPolicyInfo_Set(
    policyInfo, extensions,
    policy->valdyear, policy->valdmon, policy->valdday,
    policy->valdhour) == SUCCESS);
  ASN_Del(extensions);
  /*# FIXME : memory copy 가 효출적으로 일어나게 수정할 것 */
  VERIFY(::PKIIssuerInfo_Set(
    issuerInfo, false, caCnK.first.get(), caCnK.second.get()) == SUCCESS);

  string cdpuri;
  int certscount = 0;
  if (dynamic_cast<DBEntity*>(certHolder) && isPCRL())
  {
    TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
    certscount = getPCRL_CurrentCertsCount();
    cdpuri = getPCRL_CdpUri(certscount);
    TRACE_LOG(TMPLOG, cdpuri.c_str());
  }
  TRACE_LOG(TMPLOG, "%d, %s", isPCRL(), PRETTY_TRACE_STRING);

  ret = CERT_MakeCertificate(
    newCert.get(),
    entityInfo, reqCertInfo,
    policyInfo, issuerInfo, cdpuri.c_str());
  ASN_Del(entityInfo);
  ASN_Del(policyInfo);
  ASN_Del(issuerInfo);
  if (ret != SUCCESS)
  {
    /*# ERROR : 인증서 생성 실패 */
    /*# LOG : 인증서 생성 실패 */
    CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_GEN_CERT_N);
    e.addOpts(
      "해당 certReqMsg의 index(0부터) : %i, 에러 코드 : %i",
      reqIdx, ret);
    throw e;
  }

  // 인증서 저장
  if ((entity = dynamic_cast<DBEntity*>(certHolder)) != NULL)
  {
    DBEntityPKC *entityPKC = new DBEntityPKC(newCert.get());
    entityPKC->esid = certHolder->getSID();
    entityPKC->csid = sender->getSID();
    // conf 수신 여부에 따라 GOOD/REVOKE 결정
    entityPKC->stat = PKIDB_PKC_STAT_HOLD;
    entityPKC->psid = policy->sid;
    // partitioned crl
    if (!cdpuri.empty())
      entityPKC->cdp = cdpuri;

    if (reqCertInfo->privateKey != NULL)
      SetEncryptedPrivateKey(entityPKC, policy, reqCertInfo->privateKey);

    // FIXME - 키 복구 기관에 관한 처리!
    // ekey;            /**< 암호화된 비공개키(Not implemented) */
    // krcert[100];     /**< 비공개키 암호화에 사용된 키복구기관 인증서의 일련번호 */
    try
    {
      entityPKC->insert();

      if (!cdpuri.empty())
      {
        // cdp 포맷 문자 변경을 위한 카운트 1 증가
        char newcount[300];
        sprintf(newcount, "%d", certscount + 1);
        AuthorityLoginProfile::get()->getDP()->set(PKIDB_GLOBAL_CERT_SECTION,
            PKIDB_GLOBAL_CERT_COUNT, newcount);
      }
    }
    catch (DBCommandException)
    {
      delete entityPKC;
      /*# ERROR : 발급된 인증서를 DB에 저장하는데 실패(systemFailure(draft)) */
      /*# LOG : 생성된 인증서를 DB에 저장하는데 실패 */
      CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_INSERT_CERT_TO_DB_N);
      e.addOpt("해당 certReqMsg의 index(0부터)", reqIdx);
      throw e;
    }
    ctx.pkc.reset(entityPKC);
  }
  else
  {
    DBAuthorityPKC *authorityPKC =
      new DBAuthorityPKC(newCert.get());
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
      e.addOpt("해당 certReqMsg의 index(0부터)", reqIdx);
      throw e;
    }
    ctx.pkc.reset(authorityPKC);
  }
}

void CMP::makeCertResponse()
{
  // POP가 encCert 방식인 경우에는 응답 메시지 내의 인증서를 사용자의 공개키를 이용하여
  // hybrid방식으로 암호화 하여 전송한 뒤, 사용자로부터의 conf 메시지를 인증서를 암호화 하는데
  // 사용한 비밀키를 이용하여 검증하여야 한다.
  // 따라서, 동일한 비밀키가 인증서 암호화(복수개가 될 수도 있음)와 conf 메시지 검증에 사용되므로
  for (vector<ISSUE_CONTEXT>::iterator i = _issueCtx.begin();
    i != _issueCtx.end(); i++)
  {
    if (i->certResponse.get())
      continue;
    // response가 이미 생성되어 있는 경우(에러 response)에는 certResponse를 생성하지 않음

    try
    {
      makeOneCertResponse(*i);
    }
    catch (CMPException &e)
    {
      // error response 설정
      VERIFY(e.getErrorMsgContent());
      CertResponse *errorResponse = ASN_New(CertResponse, NULL);
      ASN_Copy(
        errorResponse->certReqId, i->certReqMsg->certReq->certReqId);
      ASN_Copy(
        errorResponse->status, e.getErrorMsgContent()->pKIStatusInfo);
      i->certResponse.reset(errorResponse, ASN_Delete);
    }
  }
}

void CMP::makeOneCertResponse(ISSUE_CONTEXT &ctx)
{
  int ret;
  DBPKC *newPKC = dynamic_cast<DBPKC *>(ctx.pkc.get());

  CertResponse *certResponse = ASN_New(CertResponse, NULL);
  ASN_Copy(certResponse->certReqId, ctx.certReqMsg->certReq->certReqId);

  /*# FIXME: PKIStatus_grantedWithMods도 처리하기 */
  VERIFY(::ASNInt_SetInt(
    certResponse->status->status, PKIStatus_accepted) == SUCCESS);
  /*# NOTE: 현재 버전에서는 CA에서 키를 생성하지 않으므로 privateKey 영역은 사용하지 않음 */
  VERIFY(::ASNSeq_NewOptional(
    pASN(&certResponse->certifiedKeyPair), ASN_SEQ(certResponse)) == SUCCESS);

  int popTech;
  VERIFY(::ASNInt_GetInt(&popTech, ctx.reqCertInfo->popTechnique) == SUCCESS);
  if (popTech != POP_Technique_EKPOPEncryptedCert)
  {
    VERIFY(::ASNChoice_Select(
      ASN_CHOICE(certResponse->certifiedKeyPair->certOrEncCert),
      CertOrEncCert_certificate) == SUCCESS);
    ASN_Copy(
      certResponse->certifiedKeyPair->certOrEncCert->choice.certificate,
      newPKC->getCertificate().get());
  }
  else
  {
    // POP이 EncCert로 되는 경우
    VERIFY(::ASNChoice_Select(
      ASN_CHOICE(certResponse->certifiedKeyPair->certOrEncCert),
      CertOrEncCert_encryptedCert) == SUCCESS);
    ASNBuf encodedCertBuf;
    RandAnsiContext randCtx;

    if (_encCertSymmKey.get() == NULL)
    {
      // 아직 키가 생성되어 있지 않은 경우 비밀키를 생성
      _encCertSymmKey.reset(
        ::ASNBuf_New(DEFAULT_SYMMETRIC_KEY_LEN), ASNBuf_Delete);

      ::RANDANSI_Initialize(&randCtx);
      ::RANDANSI_GetRandomNum(
        reinterpret_cast<unsigned char*>(
          _encCertSymmKey->data),
        DEFAULT_SYMMETRIC_KEY_LEN, &randCtx);
      _encCertSymmKey->len = DEFAULT_SYMMETRIC_KEY_LEN;
    }

    DBEntityPKC *entityPKC;
    DBAuthorityPKC *authorityPKC;

    if ((entityPKC = dynamic_cast<DBEntityPKC*>(newPKC)) != NULL)
    {
      ASNBuf_SetP(&encodedCertBuf, entityPKC->pkc.data, entityPKC->pkc.len);
    }
    else
    {
      authorityPKC =
        boost::polymorphic_downcast<DBAuthorityPKC *>(newPKC);
      ASNBuf_SetP(
        &encodedCertBuf, authorityPKC->pkc.data, authorityPKC->pkc.len);
    }

    AlgorithmIdentifier *symmAlg = ASN_New(AlgorithmIdentifier, NULL);
    AlgorithmIdentifier *hashAlg = ASN_New(AlgorithmIdentifier, NULL);
    VERIFY(::AlgorithmIdentifier_SetNid(
      symmAlg, AuthorityLoginProfile::get()->getDefaultSymmAlgNid(), NULL) == SUCCESS);
    VERIFY(::AlgorithmIdentifier_SetNid(hashAlg, NID_SHA1, NULL) == SUCCESS);
    ret = ::EncryptedValue_Set(
      certResponse->certifiedKeyPair->certOrEncCert->choice.encryptedCert,
      (unsigned char*)encodedCertBuf.data,
      encodedCertBuf.len,
      reinterpret_cast<unsigned char*>(_encCertSymmKey->data),
      _encCertSymmKey->len,
      symmAlg,
      newPKC->getCertificate()->tbsCertificate->subjectPublicKeyInfo,
      hashAlg);
    ASN_Del(symmAlg);
    ASN_Del(hashAlg);
    if (ret != SUCCESS)
    {
      /*# ERROR: Fail to make encrypted value (systemFailure(draft)) */
      /*# LOG : 생성된 인증서를 암호화 하는데 실패 */
      CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_ENCRYPT_CERT_N);
      e.addOpts(
        "해당 certReqMsg의 index(0부터) : %i, "
        "공개키 알고리즘의 OID : %o",
        ctx.reqIndex,
        &newPKC->getCertificate()->tbsCertificate->subjectPublicKeyInfo->algorithm->algorithm->oid);
      throw e;
    }
  }
  ctx.certResponse.reset(certResponse, ASN_Delete);
}

}
