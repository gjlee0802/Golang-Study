// cis headers
#include <cassert>

#include "x509pkc.h"

// pkilib headers
#include "DBObject.hpp"
#include "Socket.hpp"
#include "CnK_define.hpp"

#include "Trace.h"

#include "CMP.hpp"
#include "AuthorityLoginProfile.hpp"
#include "CMPException.hpp"
#include "PKILogTableDefine.hpp"
#include "Log.hpp"

using namespace std;
using namespace Issac::DB;

#define TMPLOG "/tmp/cmp.log"

namespace Issac
{

//////////////////////////////////////////////////////////////////////
// CMPVerifyMessageCommand Class
//////////////////////////////////////////////////////////////////////
void CMP::verifyMessage(PKIMessage *pkiMessage, PKISenderAuthInfo *authInfo)
{
  // 1. 메시지 형식 검사 및 기타 설정
  // 1.1. Header 검사
  //    Integer *pvno;
  //    GeneralName *sender;
  //    GeneralName *recip;
  //    GeneralizedTime *messageTime;       /* optional [0] */
  //    AlgorithmIdentifier *protectionAlg; /* optional [1] */
  //    KeyIdentifier *senderKID;           /* optional [2] */
  //    KeyIdentifier *recipKID;            /* optional [3] */
  //    OctetString *transactionID;         /* optional [4] */
  //    OctetString *senderNonce;           /* optional [5] */
  //    OctetString *recipNonce;            /* optional [6] */
  //    PKIFreeText *freeText;              /* optional [7] */
  //    SeqOfInfoTypeAndValue *generalInfo; /* optional [8] */

  TRACE_LOG(TMPLOG, "%s%s\n", PRETTY_TRACE_STRING_N, "1.1.1. Version 검사");
  int ver;
  ASNInt_GetInt(&ver, pkiMessage->header->pvno);
  if (ver != 1)
  {
    TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING_N);
    /*# ERROR: Error Message 전송(unsupportedVersion(draft)) */
    /*# LOG : 잘못된 메시지 ver */
    CMPSendErrorException e(LOG_CAMSGD_UNSUPPORTED_PKIMESSAGE_VERSION_N);
    e.addOpt("요청 메시지의 ver", ver);
    throw e;
  }

  TRACE_LOG(TMPLOG, "%s%s\n", PRETTY_TRACE_STRING_N,
    "1.1.2. recip 검사");
  if (pkiMessage->header->recipient->select != GeneralName_directoryName)
  {
    TRACE_LOG(TMPLOG, "%s%s\n", PRETTY_TRACE_STRING_N,
      "recip가 directoryName이 아님");
    TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING_N);
    CMPSendErrorException e(LOG_CAMSGD_INVALID_RECIPIENT_TYPE_N);
    e.addOpt("recip의 chioce 값", pkiMessage->header->recipient->select - 1);
    throw e;
  }

  if (pkiMessage->header->recipient->choice.directoryName->
    choice.rdnSequence->size == 0)
  {
    TRACE_LOG(TMPLOG, "%s%s\n", PRETTY_TRACE_STRING_N,
      "MAC Protection의 경우에만 Header->recip 필드에 NULL값을 허용");
    if (pkiMessage->header->protectionAlg->algorithm->nid !=
      NID_passwordBasedMac)
    {
      TRACE_LOG(TMPLOG, "%s%s\n", PRETTY_TRACE_STRING_N,
        "Error Message 전송(badDataFormat : recip 가 없음");
      CMPSendErrorException e(LOG_CAMSGD_MISSING_RECIPIENT_N);
      throw e;
    }
  }
  else
  {
    char recip[512];
    ::Name_SprintLine(
      recip, sizeof(recip),
      pkiMessage->header->recipient->choice.directoryName);
    if (::Name_Compare(
      pkiMessage->header->recipient->choice.directoryName,
      AuthorityLoginProfile::get()->getMyCnK().first->tbsCertificate->subject) !=
      SUCCESS)
    {
      TRACE_LOG(TMPLOG, "%s%s\n", PRETTY_TRACE_STRING_N,
        "Error Message 전송(wrongAuthority : recip should be CA");
      CMPSendErrorException e(LOG_CAMSGD_WRONG_AUTHORITY_N);
      e.addOpt("recip 값", recip);
      throw e;
    }
  }

  TRACE_LOG(TMPLOG, "%s%s\n", PRETTY_TRACE_STRING_N,
    "1.1.3. recipKID 필드 검사");
  if (pkiMessage->header->recipKID != NULL)
  {
    TRACE_LOG(TMPLOG, "%s%s\n", PRETTY_TRACE_STRING_N,
      "pkiMessage->header->recipKID != NULL");
    try
    {
      _recipCnK = AuthorityLoginProfile::get()->
        getMyCnK(pkiMessage->header->recipKID);
    }
    catch (Exception)
    {
      TRACE_LOG(TMPLOG, "%s%s\n", PRETTY_TRACE_STRING_N,
        "ERROR: Error Message 전송(wrongAuthority : recip should be CA\n"
        "LOG : recipKID 값이 CA 공개키의 KID와 일치하지 않음");
      char keyBuf[128];
      keyBuf[0] = '\0';

      CMPSendErrorException e(LOG_CAMSGD_WRONG_AUTHORITY_KID_N);
      int keyLen = ::ASNOctStr_Get(
        keyBuf, sizeof(keyBuf), pkiMessage->header->recipKID);
      if (keyLen > 0) keyBuf[keyLen] = '\0';
      e.addOpt("recipKID 값", keyBuf);
      throw e;
    }
  }
  else
  {
    TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING_N);
    _recipCnK = AuthorityLoginProfile::get()->getMyCnK();
  }
  TRACE_LOG(TMPLOG, "%s%s\n", PRETTY_TRACE_STRING_N,
    "2. protection을 검사");
  verifyProtection(pkiMessage, authInfo);
}

void CMP::verifyProtection(PKIMessage *pkiMessage, PKISenderAuthInfo *authInfo)
{
  TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING_N);
  int ret;
  char buf[128];

  switch (authInfo->select)
  {
  case PKISenderAuthInfo_secretValue:
    TRACE_LOG(TMPLOG, "%s%s\n", PRETTY_TRACE_STRING_N,
      "PKISenderAuthInfo_secretValue");
    VERIFY(::ASNOctStr_Get(
      buf, sizeof(buf),
      authInfo->choice.secretValue->secretValue) != FAIL);
    ret = ::CMP_VerifyPKIMessage(pkiMessage, NULL, buf, ::strlen(buf), 0);
    break;
  case PKISenderAuthInfo_certAndPriKey:
    TRACE_LOG(TMPLOG, "%s%s\n", PRETTY_TRACE_STRING_N,
      "PKISenderAuthInfo_certAndPriKey");
    ret = ::CMP_VerifyPKIMessage(
      pkiMessage, authInfo->choice.certAndPriKey->certificate, NULL, 0, 0);
    break;
  case PKISenderAuthInfo_revPassPhrase:
    TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING_N);
    VERIFY(::ASNOctStr_Get(
      buf, sizeof(buf),
      authInfo->choice.revPassPhrase->revPassPhrase) != FAIL);
    ret = ::CMP_VerifyPKIMessage(
      pkiMessage, NULL, buf, ::strlen(buf), 0);
    break;
  case PKISenderAuthInfo_popEncCertKey:
    {
    TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING_N);
    unsigned char symmKeyBuf[MAX_SYMMKEY_LEN];
    int symmKeyLen = ::ASNBitStr_Get(
      reinterpret_cast<char *>(symmKeyBuf), sizeof(symmKeyBuf) * 8,
      authInfo->choice.popEncCertKey->certEncKey);
    VERIFY(symmKeyLen != FAIL);
    symmKeyLen /= 8;
    ret = ::CMP_VerifyPKIMessage(
      pkiMessage, NULL, reinterpret_cast<char*>(symmKeyBuf), symmKeyLen, 0);
    break;
    }
  default :
    TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING_N);
    VERIFY(false);
    break;
  }
  TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING_N);

  if (ret != SUCCESS)
  {
    TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING_N);
    switch (ret)
    {
    case ER_CMP_WRONG_PKIMESSAGE_TIME :
      {
      TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING_N);
      /*# ERROR: Error Message 전송(badMessageCheck : 시간 검증 에러) */
      /*# LOG : PKIMessage의 시간 값이 제한된 범위를 벗어남 */
      CMPSendErrorException e(LOG_CAMSGD_WRONG_MESSAGE_TIME_N);
      TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING_N);
      time_t timeCA, timeMessage;
      ASNGenTime_GetByTimeT(&timeMessage, pkiMessage->header->messageTime);
      TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING_N);
      ::time(&timeCA);
      e.addOpts(
        "요청 메시지의 messageTime : %t, CA의 Time : %t", timeMessage, timeCA);
      TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING_N);
      throw e;
      break;
      }
    default :
      {
      TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING_N);
      CMPSendErrorException e(LOG_CAMSGD_BAD_MESSAGE_CHECK_N);
      TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING_N);
      e.addOpts(
        "요청 메시지(DER Encoded) : %a, "
        "protection 검증 방식(secret value[0], signature[1], revocation pass[2]) : %i",
        pkiMessage, authInfo->select - 1 );
      TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING_N);
      throw e;
      break;
      }
    }
  }
}

void CMP::verifyConfMessage()
{
  // POP가 encCert인 경우를 처리하기 위한 사용자 인증 정보 설정
  // 자세한 내용은 issueCert 함수와 rfc2510, rfc2511참조
  if (_encCertSymmKey.get() != NULL)
  {
    // encCert 방식을 사용한 경우
    PKISenderAuthInfo *senderAuthInfo =
      ASN_New(PKISenderAuthInfo, NULL);
    PKISenderAuthInfo_SetPopEncCertKey(
      senderAuthInfo,
      reinterpret_cast<unsigned char*>(_encCertSymmKey.get()->data),
      _encCertSymmKey.get()->len);
    _confAuthInfo.reset(senderAuthInfo, ASN_Delete);
  }
  else
  {
    // encCert 방식을 사용하지 않은 경우
    _confAuthInfo = _senderAuthInfo;
  }

  verifyMessage(_confMessage.get(), _confAuthInfo.get());

  // Message로부터 Session 정보 검증

  // 1. Nonce 값 검증
  if (_confMessage->header->recipNonce == NULL)
    /*# Conf 메시지 검증 실패시엔 에러 메시지 전송하지 않음 */
    throw CMPException(LOG_CAMSGD_MISSING_RECIPNONCE_N);
  else if (ASNOctStr_Cmp(
    _confMessage->header->recipNonce, _resMessage->header->senderNonce) != 0)
    throw CMPException(LOG_CAMSGD_WRONG_NONCE_N);

  // 2. Transaction ID 값 검증
  if (_resMessage->header->transactionID != NULL)
  {
    if (_confMessage->header->transactionID == NULL ||
      ASNOctStr_Cmp(_confMessage->header->transactionID,
        _resMessage->header->transactionID) != 0)
    {
      /*# ERROR: Transaction ID 값이 일치하지 않음 */
      CMPException e(LOG_CAMSGD_WRONG_TRANSACTION_ID_N);
      e.addOpts(
        "기존 transaction ID : %s, conf 메시지 내의 transaction ID : %s",
        _confMessage->header->transactionID->data,
        _resMessage->header->transactionID->data);
      throw e;
    }
  }
}

void CMP::verifyReqMessage()
{
  verifyMessage(_reqMessage.get(), _senderAuthInfo.get());
}

}
