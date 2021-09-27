/**
 * @file     CRLHelper.c
 *
 * @desc     CA 에서 인증서 폐지 목록 생성 관련 함수
 * @author   박지영(jypark@pentasecurity.com)
 * @since    2001.11.22
 *
 * Revision History
 *
 * @date     2001.11.22 : Start
 *
 *
 */

#include <time.h>

#include "crl.h"

#include "CRLHelper.h"

/**
 * CRL Extension template값으로부터 extension값을 생성하여 CRL의 Extensions에 추가한다.
 *
 * @param *extensions    (Out) Extension을 Extensions
 * @param  crlCount      (In)  CRL Number
 *                            (이 값이 -1 이거나 혹은 extsTemplate에 해당 영역이 없는 경우 추가되지 않음)
 * @param *pIssuerInfo   (In)  인증서 폐지 목록 발급자 정보
 * @param  baseCrlNumber (In)  생성하는 CRL이 DeltaCRL인 경우 해당 Base CRL의 CRL Number
 * @param *extTemplate   (In)  설정할 Extension에 대한 정보를 담고 있는 Template값
 * @return
 *  - SUCCESS: 성공
 */
int CRL_AddExtensions(Extensions    *extensions,
                     int            crlCount,
                     Certificate   *issuerCert,
                     int            baseCrlNumber,
                     Extension     *extTemplate)
{
  int ret;

  Extension    *ext, *extCpy;

  AuthorityKeyIdentifier *authKeyId;
  SubjectKeyIdentifier   *subjectKeyId;
  GeneralName *gnName;
  IssuerAltName          *issuerAltName;
  CRLNumber              *crlNumber;
  DeltaCRLIndicator      *deltaCRLIndicator;

  ER_RET_IF(extensions == NULL);
  ER_RET_IF(extTemplate == NULL);

  switch(extTemplate->extnID->nid)
  {
  case NID_authorityKeyIdentifier:
    authKeyId  = Extension_GetByType(NULL, extTemplate, AuthorityKeyIdentifier);
    if (authKeyId == NULL)
      return FAIL;
    if (authKeyId->keyIdentifier != NULL)
    {
      subjectKeyId = Extensions_GetByType(NULL, issuerCert->tbsCertificate->extensions,
                                           SubjectKeyIdentifier, NID_subjectKeyIdentifier);
      if (subjectKeyId != NULL)
      {
        ASN_Copy(authKeyId->keyIdentifier, subjectKeyId);
        ASN_Del(subjectKeyId);
      }
      else
      {
        ASN_Del(authKeyId);
        return ER_MAKE_CRL_FAIL_TO_GET_ISSUER_SUBJECTKEYID;
      }
    }
    else
    {
      /*# ERROR: KeyIdentifier 는 반드시 있어야 함(정책상) */
      ASN_Del(authKeyId);
      return ER_MAKE_CRL_INVALID_AUTHORITYKEYID;
    }

    if (authKeyId->authorityCertIssuer != NULL)
    {
      if (authKeyId->authorityCertSerialNumber == NULL)
      {
        /*# ERROR: authorityCertIssuer와 authorityCertSerialNumber는 함께 설정되어야 함 */
        return ER_MAKE_CRL_INVALID_AUTHORITYKEYID;
      }
      ASN_Copy(authKeyId->authorityCertSerialNumber, issuerCert->tbsCertificate->serialNumber);
      gnName = ASN_New(GeneralName, NULL);
      ret = GenName_Set(gnName, GeneralName_directoryName, issuerCert->tbsCertificate->issuer);
      if (ret != SUCCESS)
      {
        ASN_Del(gnName);
        ASN_Del(authKeyId);
        return FAIL;
      }
      ASNSeqOf_Reset(ASN_SEQOF(authKeyId->authorityCertIssuer));
      GenNames_AddGenName(authKeyId->authorityCertIssuer, gnName);
    }
    Extensions_AddByNid(extensions, NID_authorityKeyIdentifier, 
      ASNBool_Get(extTemplate->critical), ASN(authKeyId));
    break;
  case NID_issuerAltName:
    ext = Extensions_GetPByNid(issuerCert->tbsCertificate->extensions, NID_subjectAltName);
    if (ext != NULL)
    {
      issuerAltName = Extension_GetByType(NULL, ext, IssuerAltName);
      if (issuerAltName == NULL)
        return FAIL;
      Extensions_AddByNid(extensions,NID_issuerAltName, 
        ASNBool_Get(extTemplate->critical), ASN(issuerAltName));
      ASN_Del(issuerAltName);
    }
    break;
  case NID_cRLNumber:
    if (crlCount > -1)
    {
      crlNumber = Extension_GetByType(NULL, extTemplate, CRLNumber);
      if (crlNumber == NULL)
        return FAIL;
      ASNInt_SetInt(crlNumber, crlCount);
      Extensions_AddByNid(extensions, NID_cRLNumber,
        ASNBool_Get(extTemplate->critical), ASN(crlNumber));
      ASN_Del(crlNumber);
    }
    break;
  case NID_deltaCRLIndicator:
    deltaCRLIndicator = ASN_New(DeltaCRLIndicator, NULL);
    ASNInt_SetInt(deltaCRLIndicator, baseCrlNumber);
    Extensions_AddByNid(extensions, NID_deltaCRLIndicator, 
      ASNBool_Get(extTemplate->critical), ASN(deltaCRLIndicator));
    ASN_Del(deltaCRLIndicator);
    break;
  case NID_issuingDistributionPoint:
  default:
    extCpy = (Extension*)ASN_Dup(ASN(extTemplate));
    Extensions_AddP(extensions, extCpy);
    break;
  /* Not supported : 
  case NID_crlScope
  case NID_deltaInfo:
  case NID_baseUpdateTime:
  */
  }

  return SUCCESS;
}


RevokedCertificate *CRL_NewRevokedCertificate(
    CertificateSerialNumber *serialNumber,
    time_t                   revocationTime,
    int                      reason,
    time_t                   invalidityTime,
    Name                    *certIssuerName,
    Extensions              *extsTemplate)
{
  RevokedCertificate *newRevokedCert;
  struct tm revocationDate;

  int i;
  Extension           *ext, *extCpy;
  ReasonCode          *reasonCode;
  InvalidityDate      *invalidityDate;
  struct tm            invalidityTm;
  CertificateIssuer   *certIssuer;

  ER_RET_VAL_IF(serialNumber == NULL, NULL);

  newRevokedCert = ASN_New(RevokedCertificate, NULL);

  // 1. 기본 Fields 설정
  ASN_Copy(newRevokedCert->userCertificate, serialNumber);

  gmtime_r(&revocationTime, &revocationDate);
  Time_Set(newRevokedCert->revocationDate, &revocationDate);

  // 2. Extensions 설정
  if (extsTemplate == NULL)
    return newRevokedCert;

  ASNSeq_NewOptional(pASN(&newRevokedCert->crlEntryExtensions), ASN_SEQ(newRevokedCert));
  // 2.1. 해석할 수 있는 Extensions 설정
  ext = Extensions_GetPByNid(extsTemplate, NID_reasonCode);
  if (ext != NULL)
  {
    reasonCode = Extension_GetByType(NULL, ext, ReasonCode);
    if (reasonCode == NULL)
    {
      ASN_Del(newRevokedCert);
      return NULL;
    }
    
    ASNEnum_Set(reasonCode, reason);
    Extensions_AddByNid(newRevokedCert->crlEntryExtensions, NID_reasonCode,
      ASNBool_Get(ext->critical), ASN(reasonCode));
    ASN_Del(reasonCode);
  }

  ext = Extensions_GetPByNid(extsTemplate, NID_invalidityDate);
  if (ext != NULL && invalidityTime != 0)
  {
    invalidityDate = Extension_GetByType(NULL, ext, InvalidityDate);
    if (invalidityDate == NULL)
    {
      ASN_Del(newRevokedCert);
      return NULL;
    }
    gmtime_r(&invalidityTime, &invalidityTm);
    ASNGenTime_Set(invalidityDate, &invalidityTm);
    Extensions_AddByNid(newRevokedCert->crlEntryExtensions, NID_invalidityDate,
      ASNBool_Get(ext->critical), ASN(invalidityDate));
    ASN_Del(invalidityDate);
  }

  ext = Extensions_GetPByNid(extsTemplate, NID_certificateIssuer);
  if (ext != NULL && certIssuerName != 0)
  {
    GeneralName *gnName;
    certIssuer = Extension_GetByType(NULL, ext, CertificateIssuer);
    if (certIssuer == NULL)
    {
      ASN_Del(newRevokedCert);
      return NULL;
    }
    gnName = ASN_New(GeneralName, NULL);
    GenName_Set(gnName, GeneralName_directoryName, certIssuerName);
    ASNSeqOf_Reset(ASN_SEQOF(certIssuer));
    GenNames_AddGenName(certIssuer, gnName);

    Extensions_AddByNid(newRevokedCert->crlEntryExtensions, NID_certificateIssuer,
      ASNBool_Get(ext->critical), ASN(certIssuer));
    ASN_Del(certIssuer);
  }

  ext = Extensions_GetPByNid(extsTemplate, NID_holdInstructionCode);
  if (ext != NULL && reason == CRLReason_certificateHold)
  {
    extCpy = (Extension*)ASN_Dup(ASN(ext));
    Extensions_AddP(newRevokedCert->crlEntryExtensions, extCpy);
  }

  // 2.2. 해석할 수 없는 Extensions 설정
  for (i=0; i< extsTemplate->size; i++)
  {
    switch (extsTemplate->member[i]->extnID->nid)
    {
      case NID_reasonCode:
      case NID_invalidityDate:
      case NID_certificateIssuer:
        break;
      default:
        extCpy = (Extension*)ASN_Dup(ASN(extsTemplate->member[i]));
        Extensions_AddP(newRevokedCert->crlEntryExtensions, extCpy);
        break;
    }
  }

  return newRevokedCert;
}

                                             
