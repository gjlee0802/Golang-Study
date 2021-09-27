/**
 * @file     CertHelper.c
 *
 * @desc     CA 에서 인증서 생성 관련 함수
 * @author   박지영(jypark@pentasecurity.com)
 * @since    2001.11.16
 *
 * Revision History
 *
 * @date     2001.11.16 : Start
 * @date     2001.12.12 : Subject Alt Name 사용 방식 변화에 따라서 
 *           CERT_AddCertExtensions 파라메터 변경
 *
 */

// standard headers
#include <stdlib.h>
#include <string.h>

// cis headers
#include "pkiinfo.h"
#include "pkiinfo.h"
#include "sha1.h"
#include "hash_op.h"

#include "CertHelper.h"
#include "Trace.h"

#define TMPLOG "/tmp/libpki.log"

/**
 * 인증서를 생성한다.
 */
int CERT_MakeCertificate(Certificate   *newCert,
                    PKIEntityInfo *entityInfo,
                    PKIReqCertInfo *reqCertInfo,
                    PKIPolicyInfo *policyInfo,
                    PKIIssuerInfo *issuerInfo, 
                    const char *cdpUri)
{
  int ret, i;
  Certificate *caCert;

  Nid nidSigHashAlg, nidPkAlg, nidHashAlg;

  int year, month, day, hour;
  struct tm tmNotBefore, tmNotAfter;
  struct tm tmNotAfterCA, tmNotAfterEntity;
  time_t timeNow;
  time_t timeNotAfter, timeNotAfterCA, timeNotAfterEntity;

  ASNBuf  *encodedCertBuf, *signedCertBuf;

  ER_RET_IF(newCert == NULL);
  ER_RET_IF(entityInfo == NULL ||
            reqCertInfo == NULL ||
            policyInfo == NULL ||
            issuerInfo == NULL);

  timeNow = time(NULL);
  if (issuerInfo->select != PKIIssuerInfo_selfSigned)
    caCert = issuerInfo->choice.certAndPriKey->certificate;

  // 1. 기본 필드 설정
  //   Version                 *version;
  //   CertificateSerialNumber *serialNumber;
  //   AlgorithmIdentifier     *signature;
  //   Name                    *issuer;
  //   Validity                *validity;
  //   Name                    *subject;
  //   SubjectPublicKeyInfo    *subjectPublicKeyInfo;
  //   UniqueIdentifier        *issuerUniqueId; /* optional */
  //   UniqueIdentifier        *subjectUniqueId; /* optional */
  Version_Set(newCert->tbsCertificate->version, CERT_VER3);
  if (issuerInfo->select == PKIIssuerInfo_selfSigned)
  {
    // Self-Signed 인증서
    
    CertificateSerialNumber_Gen(newCert->tbsCertificate->serialNumber, 
                                entityInfo->subject,
                                entityInfo->subject);
    /*# NOTE: CA의 서명 hashAlg은 SHA1으로 고정 */
    nidPkAlg      = reqCertInfo->publicKey->algorithm->algorithm->nid;
    nidHashAlg    = NID_SHA1;
    nidSigHashAlg = AlgNid_GetSigAlgNid(nidPkAlg, nidHashAlg);
    AlgorithmIdentifier_SetNid(newCert->tbsCertificate->signature, 
      nidSigHashAlg, NULL);
    ASN_Copy(newCert->tbsCertificate->issuer, entityInfo->subject);

    gmtime_r(&timeNow, &tmNotBefore);
    tmNotAfter = tmNotBefore;
    ASNInt_GetInt(&year, policyInfo->validityTerm->year);
    ASNInt_GetInt(&month, policyInfo->validityTerm->month);
    ASNInt_GetInt(&day, policyInfo->validityTerm->day);
    ASNInt_GetInt(&hour, policyInfo->validityTerm->hour);
    tmNotAfter.tm_year += year;
    tmNotAfter.tm_mon  += month;
    tmNotAfter.tm_mday += day;
    tmNotAfter.tm_hour += hour;
    mktime(&tmNotAfter);

    Validity_Set(newCert->tbsCertificate->validity, &tmNotBefore, &tmNotAfter);

    ASN_Copy(newCert->tbsCertificate->subject, entityInfo->subject);
    ASN_Copy(newCert->tbsCertificate->subjectPublicKeyInfo,
           reqCertInfo->publicKey);
    /*# NOTE: 현 시스템에서는 subjectUniqueId는 사용하지 않는다. */
  }
  else
  {
    // 일반 인증서
    CertificateSerialNumber_Gen(newCert->tbsCertificate->serialNumber, 
                                caCert->tbsCertificate->subject,
                                entityInfo->subject);
    nidPkAlg    = caCert->tbsCertificate->subjectPublicKeyInfo->algorithm->
      algorithm->nid;
    nidHashAlg  = issuerInfo->choice.certAndPriKey->hashAlg->algorithm->nid;
    nidSigHashAlg = AlgNid_GetSigAlgNid(nidPkAlg, nidHashAlg);
    AlgorithmIdentifier_SetNid(newCert->tbsCertificate->signature, 
      nidSigHashAlg, NULL);
    
    ASN_Copy(newCert->tbsCertificate->issuer, caCert->tbsCertificate->subject);

    // 유효기간 : 현재 ~ MIN(Policy에 명시된 기간, Entity값에 명시된 기간, 
    // CA인증서의 유효기간)
    timeNow = time(&timeNow);
    gmtime_r(&timeNow, &tmNotBefore);
    tmNotAfter  = tmNotBefore;
    ASNInt_GetInt(&year, policyInfo->validityTerm->year);
    ASNInt_GetInt(&month, policyInfo->validityTerm->month);
    ASNInt_GetInt(&day, policyInfo->validityTerm->day);
    ASNInt_GetInt(&hour, policyInfo->validityTerm->hour);
    tmNotAfter.tm_year += year;
    tmNotAfter.tm_mon  += month;
    tmNotAfter.tm_mday += day;
    tmNotAfter.tm_hour += hour;
    mktime(&tmNotAfter);

    GmtimeToLocaltime(&tmNotAfter, &tmNotAfter);
    timeNotAfter    = mktime(&tmNotAfter);
    LocaltimeToGmtime(&tmNotAfter, &tmNotAfter);
    Time_Get(&tmNotAfterCA, caCert->tbsCertificate->validity->notAfter);
    GmtimeToLocaltime(&tmNotAfterCA, &tmNotAfterCA);
    timeNotAfterCA  = mktime(&tmNotAfterCA);
    LocaltimeToGmtime(&tmNotAfterCA, &tmNotAfterCA);

    if (entityInfo->notAfter != NULL)
    {
      Time_Get(&tmNotAfterEntity, entityInfo->notAfter);
      GmtimeToLocaltime(&tmNotAfterEntity, &tmNotAfterEntity);
      timeNotAfterEntity = mktime(&tmNotAfterEntity);
      if (timeNotAfterEntity != 0 && timeNotAfterEntity < timeNotAfter)
      {
        timeNotAfter = timeNotAfterEntity;
        LocaltimeToGmtime(&tmNotAfterEntity, &tmNotAfterEntity);
        memcpy(&tmNotAfter, &tmNotAfterEntity, sizeof(struct tm));
      }
    }

    if (timeNotAfter > timeNotAfterCA)
    {
      // CA인증서 유효기간이 가장 최근
      if (timeNow > timeNotAfterCA)
        return ER_MAKE_CERT_INVALID_VALIDITY;
      Validity_Set(newCert->tbsCertificate->validity, &tmNotBefore, 
        &tmNotAfterCA);
    }
    else
    {
      // Policy에 명시된 기간이 가장 최근
      if (timeNow > timeNotAfter)
        return ER_MAKE_CERT_INVALID_VALIDITY;
      Validity_Set(newCert->tbsCertificate->validity, &tmNotBefore, 
        &tmNotAfter);
    }

    ASN_Copy(newCert->tbsCertificate->subject, entityInfo->subject);
    ASN_Copy(newCert->tbsCertificate->subjectPublicKeyInfo,
             reqCertInfo->publicKey);
    if (caCert->tbsCertificate->subjectUniqueId != NULL)
    {
      ASNSeq_NewOptional(pASN(&newCert->tbsCertificate->issuerUniqueId), 
                         ASN_SEQ(newCert->tbsCertificate));
      ASN_Copy(newCert->tbsCertificate->issuerUniqueId, 
        caCert->tbsCertificate->subjectUniqueId);
    }
    /*# NOTE: 현 시스템에서는 subjectUniqueId는 사용하지 않는다. */
  }
  
  // 1.2. 확장 필드 설정
  ASNSeq_NewOptional(pASN(&newCert->tbsCertificate->extensions), 
    ASN_SEQ(newCert->tbsCertificate));
  for (i=0; i< policyInfo->extsTemplate->size; i++)
  {
    ret = CERT_AddCertExtensions(newCert,
                            policyInfo->extsTemplate->member[i],
                            entityInfo,
                            reqCertInfo,
                            issuerInfo, cdpUri);
    if (ret != SUCCESS)
      return ret;
  }

  if (newCert->tbsCertificate->extensions->size == 0)
  {
    // 확장 필드 값이 없는 경우
    ASNSeq_DelOptional(pASN(&newCert->tbsCertificate->extensions), 
      ASN_SEQ(newCert->tbsCertificate));
    if (newCert->tbsCertificate->subjectUniqueId != NULL ||
      newCert->tbsCertificate->issuerUniqueId != NULL)
    {
      Version_Set(newCert->tbsCertificate->version, CERT_VER2);
    }
    else
    {
      Version_Set(newCert->tbsCertificate->version, CERT_VER1);
    }
  }

  // 1.3. 인증서 서명
  //      서명 알고리즘 : CA 비공개키의 알고리즘과 CA 인증서 자체의 서명에 
  //      사용된 해시 알고리즘의 조합
  encodedCertBuf  = ASN_EncodeDER(newCert->tbsCertificate);
  if (encodedCertBuf == NULL)
  {
    /*# ERROR: Fail to encode certificate */
    return FAIL;
  }
  if (issuerInfo->select == PKIIssuerInfo_selfSigned)
  {
    ret = CKM_Sign(&signedCertBuf, 
                   &nidSigHashAlg,
                   (unsigned char*)encodedCertBuf->data,
                   encodedCertBuf->len,
                   reqCertInfo->privateKey,
                   NULL,
                   reqCertInfo->param,
                   AlgNid_GetHashAlgDesc(nidHashAlg));
  }
  else
  {
    ret = CKM_Sign(&signedCertBuf, 
                   &nidSigHashAlg,
                   (unsigned char*)encodedCertBuf->data,
                   encodedCertBuf->len,
                   issuerInfo->choice.certAndPriKey->privateKey,
                   issuerInfo->choice.certAndPriKey->certificate,
                   issuerInfo->choice.certAndPriKey->param,
                   AlgNid_GetHashAlgDesc(nidHashAlg));
  }
  ASNBuf_Del(encodedCertBuf);
  if (ret != SUCCESS)
  {
    /*# ERROR: Fail to sign certificate */
    return FAIL;
  }
  AlgorithmIdentifier_SetNid(newCert->signatureAlgorithm, nidSigHashAlg, NULL);
  ASNBitStr_SetASNBuf(newCert->signatureValue, signedCertBuf);
  ASNBuf_Del(signedCertBuf);

  return SUCCESS;
}

int CERT_AddCertExtensions(Certificate *newCert,
    Extension *extTemplate,
    PKIEntityInfo *entityInfo,
    PKIReqCertInfo *reqCertInfo,
    PKIIssuerInfo *issuerInfo,
    const char *cdpUri)
{
  int ret, i, j;
  Extensions *extensions;
  Certificate *caCert;

  Extension  *extCpy;
  SubjectKeyIdentifier    *subjectKeyId;
  PrivateKeyUsagePeriod   *priKeyUsagePeriod;
  IssuerAltName           *issuerAltName;
  SubjectAltName          *subjectAltName, *subjectAltNameTempl;
  AuthorityKeyIdentifier  *authKeyId;
  GeneralName             *gnName;
  struct tm vilidity, usage;
  time_t usageNotBefore, usageNotAfter;

  ER_RET_IF(newCert == NULL ||
            newCert->tbsCertificate == NULL);
  ER_RET_IF(extTemplate == NULL ||
            entityInfo == NULL ||
            reqCertInfo == NULL ||
            issuerInfo == NULL);
  ER_RET_IF(newCert->tbsCertificate->extensions == NULL);

  extensions = newCert->tbsCertificate->extensions;
  if (issuerInfo->select != PKIIssuerInfo_selfSigned)
    caCert = issuerInfo->choice.certAndPriKey->certificate;

  switch (extTemplate->extnID->nid)
  {
  case NID_subjectKeyIdentifier:
    // 1. "id-ce-subjectKeyIdentifier", "주체 키 식별자" : 
    //    CA에서 인증서 발급시 설정
    if ( reqCertInfo->subjectKeyId != NULL ) 
    {
      Extensions_AddByNid(extensions, NID_subjectKeyIdentifier, 
        ASNBool_Get(extTemplate->critical), ASN(reqCertInfo->subjectKeyId));
    } 
    else 
    {
      subjectKeyId = (SubjectKeyIdentifier*)KeyIdentifier_Gen(reqCertInfo->
        publicKey->subjectPublicKey);
      Extensions_AddByNid(extensions, NID_subjectKeyIdentifier, 
        ASNBool_Get(extTemplate->critical), ASN(subjectKeyId));
      ASN_Del(subjectKeyId);    
    }
    break;
  case NID_privateKeyUsagePeriod:
    // 3. "id-ce-privateKeyUsagePeroid", "비공개키 사용 기간"
    //    : CA에서 인증서 발급시 설정
    //    Template내에는 notBefore는 인증서의 Vality의 notBefore로부터 며칠 
    //    이후, notAfter는  인증서의 Valdity의 notAfter로부터 며칠 
    //    이전까지인지가 저장되어 있다.
    priKeyUsagePeriod = Extension_GetByType(NULL, extTemplate, 
      PrivateKeyUsagePeriod);
    if (priKeyUsagePeriod == NULL)
      return FAIL;
    if (priKeyUsagePeriod->notBefore != NULL)
    {
      PrivateKeyUsagePeriod_GetNotBefore(&usage, priKeyUsagePeriod);
      Time_Get(&vilidity, newCert->tbsCertificate->validity->notBefore);
      vilidity.tm_mday += usage.tm_yday;  // mktime에서 tm_yday값은 ignored 됨
      usageNotBefore = mktime(&vilidity);
      PrivateKeyUsagePeriod_Set(priKeyUsagePeriod, &vilidity, NULL);
    }

    if (priKeyUsagePeriod->notAfter != NULL)
    {
      PrivateKeyUsagePeriod_GetNotAfter(&usage, priKeyUsagePeriod);
      Time_Get(&vilidity, newCert->tbsCertificate->validity->notAfter);
      vilidity.tm_mday -= usage.tm_yday;  // mktime에서 tm_yday값은 ignored 됨
      usageNotAfter = mktime(&vilidity);
      PrivateKeyUsagePeriod_Set(priKeyUsagePeriod, NULL, &vilidity);
    }
    
    if (usageNotAfter < usageNotAfter)
    {
      ASN_Del(priKeyUsagePeriod);
      return ER_MAKE_CERT_INVALID_PRIVATEKEYUSAGEPERIOD;
    }

    Extensions_AddByNid(extensions, NID_privateKeyUsagePeriod,
      ASNBool_Get(extTemplate->critical), ASN(priKeyUsagePeriod));
    ASN_Del(priKeyUsagePeriod);
    break;
  case NID_subjectAltName:
    // 4. "id-ce-subjectAltName", "주체 대체 이름" : CA에서 인증서 발급시 설정
    if (entityInfo->subAltName != 0)
    {
      subjectAltName = ASN_New(SubjectAltName, NULL);
      subjectAltNameTempl = Extension_GetByType(NULL, extTemplate, 
        SubjectAltName);
      for(i=0; i< subjectAltNameTempl->size; i++)
      {
        for(j=0; j< entityInfo->subAltName->size; j++)
        {
          if (subjectAltNameTempl->member[i]->select == 
              entityInfo->subAltName->member[j]->select)
          {
            gnName = (GeneralName*)ASN_Dup(ASN(entityInfo->subAltName->
              member[j]));
            GenNames_AddGenName(subjectAltName, gnName);
          }
        }
      }
      if (subjectAltName->size != 0)
      {
        Extensions_AddByNid(extensions,NID_subjectAltName, 
          ASNBool_Get(extTemplate->critical), ASN(subjectAltName));
      }
      ASN_Del(subjectAltName);
      ASN_Del(subjectAltNameTempl);
    }
    break;
  case NID_issuerAltName:
    // 5. "id-ce-issuerAltName", "발급자 대체 이름" : CA에서 인증서 발급시 설정
    if (issuerInfo->select == PKIIssuerInfo_selfSigned)
    {
      extCpy = Extensions_GetPByNid(extensions, NID_subjectAltName);
      if (extCpy != NULL)
      {
        issuerAltName = Extension_GetByType(NULL, extCpy, IssuerAltName);
        Extensions_AddByNid(extensions,
          NID_issuerAltName, ASNBool_Get(extTemplate->critical), 
            ASN(issuerAltName));
        ASN_Del(issuerAltName);
      }
    }
    else
    {
      extCpy = Extensions_GetPByNid(caCert->tbsCertificate->extensions, 
        NID_subjectAltName);
      if (extCpy != NULL)
      {
        issuerAltName = Extension_GetByType(NULL, extCpy, IssuerAltName);
        Extensions_AddByNid(extensions,NID_issuerAltName, 
          ASNBool_Get(extTemplate->critical), ASN(issuerAltName));
        ASN_Del(issuerAltName);
      }
    }
    break;
  case NID_authorityKeyIdentifier:
    if (issuerInfo->select == PKIIssuerInfo_selfSigned)
    {
      // RootCA 인증서 : KeyIdentifier만을 설정
      authKeyId  = Extension_GetByType(NULL, extTemplate, 
        AuthorityKeyIdentifier);
      if (authKeyId == NULL)
      {
        /*# 기존 버전과의 호완을 위해..
         *  Decoding이 안되는 경우에는 keyidentifier만 사용하는 것으로 가정 
         */
        authKeyId = ASN_New(AuthorityKeyIdentifier, NULL);
        ASNSeq_NewOptional(pASN(&authKeyId->keyIdentifier), ASN_SEQ(authKeyId));
      }
      if (authKeyId->authorityCertIssuer != NULL)
        ASNSeq_DelOptional(pASN(&authKeyId->authorityCertIssuer), ASN_SEQ(authKeyId));
      if (authKeyId->authorityCertSerialNumber != NULL)
        ASNSeq_DelOptional(pASN(&authKeyId->authorityCertSerialNumber), ASN_SEQ(authKeyId));

      if (authKeyId->keyIdentifier != NULL)
      {
        subjectKeyId = Extensions_GetByType(NULL, extensions,
          SubjectKeyIdentifier, NID_subjectKeyIdentifier);
        if (subjectKeyId != NULL)
        {
          ASN_Copy(authKeyId->keyIdentifier, subjectKeyId);
          ASN_Del(subjectKeyId);
          Extensions_AddByNid(extensions, NID_authorityKeyIdentifier, 
            ASNBool_Get(extTemplate->critical), ASN(authKeyId));
        }
        else
        {
          subjectKeyId = (SubjectKeyIdentifier*)KeyIdentifier_Gen(reqCertInfo->publicKey->subjectPublicKey);
          ASN_Copy(authKeyId->keyIdentifier, subjectKeyId);
          ASN_Del(subjectKeyId);
          Extensions_AddByNid(extensions, NID_authorityKeyIdentifier, 
            ASNBool_Get(extTemplate->critical), ASN(authKeyId));
        }          
      }
      ASN_Del(authKeyId);
    } 
    else
    {
      // 일반 인증서
      authKeyId  = Extension_GetByType(NULL, extTemplate, AuthorityKeyIdentifier);
      if (authKeyId == NULL)
      {
        /*# 기존 버전과의 호완을 위해..
         *  Decoding이 안되는 경우에는 keyidentifier만 사용하는 것으로 가정 
         */
        authKeyId = ASN_New(AuthorityKeyIdentifier, NULL);
        ASNSeq_NewOptional(pASN(&authKeyId->keyIdentifier), ASN_SEQ(authKeyId));
      }
      if (authKeyId->keyIdentifier != NULL)
      {
        subjectKeyId = Extensions_GetByType(NULL, 
          caCert->tbsCertificate->extensions,
          SubjectKeyIdentifier, NID_subjectKeyIdentifier);
        if (subjectKeyId != NULL)
        {
          ASN_Copy(authKeyId->keyIdentifier, subjectKeyId);
          ASN_Del(subjectKeyId);
        }
        else
        {
          ASN_Del(authKeyId);
          return ER_MAKE_CERT_FAIL_TO_GET_ISSUER_SUBJECTKEYID;
        }
      }
      else
      {
        /*# ERROR: KeyIdentifier 는 반드시 있어야 함(정책상) */
        ASN_Del(authKeyId);
        return ER_MAKE_CERT_INVALID_AUTHORITYKEYID;
      }

      if (authKeyId->authorityCertIssuer != NULL)
      {
        if (authKeyId->authorityCertSerialNumber == NULL)
        {
          /*# ERROR: authorityCertIssuer와 authorityCertSerialNumber는 
              함께 설정되어야 함 */
          return ER_MAKE_CERT_INVALID_AUTHORITYKEYID;
        }
        ASN_Copy(authKeyId->authorityCertSerialNumber, 
          caCert->tbsCertificate->serialNumber);
        gnName = ASN_New(GeneralName, NULL);
        ret = GenName_Set(gnName, GeneralName_directoryName, 
          caCert->tbsCertificate->issuer);
        if (ret != SUCCESS)
        {
          ASN_Del(gnName);
          return FAIL;
        }
        ASNSeqOf_Reset(ASN_SEQOF(authKeyId->authorityCertIssuer));
        GenNames_AddGenName(authKeyId->authorityCertIssuer, gnName);
      }
      Extensions_AddByNid(extensions, NID_authorityKeyIdentifier, 
        ASNBool_Get(extTemplate->critical), ASN(authKeyId));
    }// if (issuerInfo->select == PKIIssuerInfo_selfSigned)
    break;
  case NID_cRLDistributionPoints:
    // 8. "id-ce-cRLDistributionPoints", "CRL 배포 지점"   
    {
      // by hrcho - override URI for Partitioned CRL
			int critical;
      CRLDistributionPoints *cdp;

      extCpy = (Extension*)ASN_Dup(ASN(extTemplate));
      cdp = Extension_GetByType(&critical, extCpy, 
          CRLDistributionPoints);
      if (cdp && cdpUri && strlen(cdpUri))
      {
        int i, j;

        TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
        for (i = 0; i < cdp->size; ++i)
        {
          DistributionPointName *dpname = cdp->member[i]->distributionPoint;
          TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
          if (dpname == NULL || dpname->select != 
              DistributionPointName_fullName)
            break;
          TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);

          for (j = 0; j < dpname->choice.fullName->size; ++j)
          {
            TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
            if (dpname->choice.fullName->member[j]->select == 
                GeneralName_uniformResourceIdentifier)
            {
              TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
              GenName_Set(dpname->choice.fullName->member[j], 
                  GeneralName_uniformResourceIdentifier, cdpUri, 
                  strlen(cdpUri));
              TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
            }
            TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
          }
          TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
        }
        Extension_SetByNid(extCpy, NID_cRLDistributionPoints, critical,
            ASN(cdp));
        ASN_Del(cdp);
      }
      TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);

    }
    Extensions_AddP(extensions, extCpy);
    TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
    break;
  case NID_keyUsage:
    // 2. "id-ce-keyUsage", "키 사용"
  case NID_basicConstraints:
    // 6. "id-ce-basicConstraints", "기본 제한"
  case NID_nameConstraints:
    // 7. "id-ce-nameConstraints", "이름 제한"
  case NID_certificatePolicies:
    // 9. "id-ce-certificatePolicies", "인증서 정책"
  case NID_policyMappings:
    // 10. "id-ce-policyMappings", "인증 정책 매핑" 
  case NID_policyConstraints:
    // 11. "id-ce-policyConstraints", "인증서 정책 제한"
  case NID_extKeyUsage:
    // 12. "id-ce-extKeyUsage", "확장 키 사용" 
  default:
    /*# NOTE: 등록되어 있지 않은 Extension은 그냥 복사해서 넣도록 함
        (검토 바람.) */
    extCpy = (Extension*)ASN_Dup(ASN(extTemplate));
    Extensions_AddP(extensions, extCpy);
    break;
  }
  return SUCCESS;
}

/**
 * 공개키의 길이(bit)를 구한다. 
 * 이 함수에서 구하는 공개키의 길이는 공개키 데이터의 bit수를 의미하며 
 * 최상위 bit가 1이 아닐 수도 있다.
 * 공개키의 길이는 128단위로 반올림 한 값을 리턴
 */
ERT CERT_GetKeyBitLength(int *lenKeyBit, PublicKeyInfo *pubKey)
{

  Nid nid;
  int nKeyBitLen;
  unsigned char firstByte;

  RSAPublicKey *rsaKey;
  DSAPublicKey *dsaKey;
  KCDSAPublicKey *kcdsaKey;
  ASNBuf  pubKeyBuf;

  ER_RET_IF(lenKeyBit == NULL ||
            pubKey     == NULL);

  *lenKeyBit  = -1;

  nKeyBitLen  = -1;
  nid = pubKey->algorithm->algorithm->nid;
  ASNBuf_SetP(&pubKeyBuf, 
              pubKey->subjectPublicKey->data + 1,
              pubKey->subjectPublicKey->len - 1);
  switch (nid) 
  {
  case NID_rsaEncryption:
    rsaKey = ASN_New(RSAPublicKey, &pubKeyBuf);

    ER_RET_VAL_IF(!rsaKey, ER_CERT_INVALID_PUBLICKEYINFO);

    nKeyBitLen  = rsaKey->modulus->len * 8;
    firstByte = rsaKey->modulus->data[0];
    ASN_Del(rsaKey);

    break;
  case NID_dsa:
    dsaKey = ASN_New(DSAPublicKey, &pubKeyBuf);

    ER_RET_VAL_IF(!dsaKey, ER_CERT_INVALID_PUBLICKEYINFO);

    nKeyBitLen = dsaKey->len * 8;
    firstByte = dsaKey->data[0];
    ASN_Del(dsaKey);

    break;
  case NID_kCDSA1:
    kcdsaKey = ASN_New(KCDSAPublicKey, &pubKeyBuf);

    ER_RET_VAL_IF(!kcdsaKey, ER_CERT_INVALID_PUBLICKEYINFO);

    nKeyBitLen = kcdsaKey->len * 8;
    firstByte = kcdsaKey->data[0];
    ASN_Del(kcdsaKey);

    break;
  case NID_kCDSA:
    kcdsaKey = ASN_New(KCDSAPublicKey, &pubKeyBuf);

    ER_RET_VAL_IF(!kcdsaKey, ER_CERT_INVALID_PUBLICKEYINFO);

    nKeyBitLen = kcdsaKey->len * 8;
    firstByte = kcdsaKey->data[0];
    ASN_Del(kcdsaKey);

    break;
  default:
    return ER_CERT_UNKNOWN_PUBLICKEY_ALG;
  }
  
  nKeyBitLen = ((nKeyBitLen + 64)/128) * 128;

  *lenKeyBit  = nKeyBitLen;
  return SUCCESS;
}

/**
 * 비공개키를 hash하여 대칭키를 생성한다.
 */
ERT CERT_MakeSymmKeyFromPK(unsigned char *bufSymmKey, int lenSymmKey, 
  PrivateKeyInfo *priKey)
{
  HashContext hashCtx;
  unsigned char buf[64];
  int len;
  ASNBuf *bufPrivateKey;

  ER_RET_IF(priKey == NULL);

  bufPrivateKey = ASN_EncodeDER(priKey);

  ER_RET_IF(bufPrivateKey == NULL);

  HASH_Initialize(&hashCtx, SHA1);
  HASH_Update(&hashCtx, (unsigned char *)(bufPrivateKey->data), 
    bufPrivateKey->len);
  HASH_Finalize(buf, (BWT *)(&len), &hashCtx);

  ASNBuf_Del(bufPrivateKey);

  ER_RET_IF(lenSymmKey > len);

  memcpy(bufSymmKey, buf, lenSymmKey);

  return SUCCESS;
}

