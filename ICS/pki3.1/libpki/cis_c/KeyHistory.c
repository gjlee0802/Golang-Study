/**
 * @file     KeyHistory.c
 *
 * @desc     Key History 처리 함수들
 * @author   조현래 (hrcho@pentasecurity.com)
 * @since    2003.07.18
 *
 * Revision History
 *
 * @date     2003.07.18 : Start
 *
 *
 */
#include <string.h>
#include <stdlib.h>
#ifdef WIN32
#include <io.h>
#include <direct.h>
#include <windows.h>
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")
#else
#include <unistd.h>
#endif

// CIS headers
#include "base_define.h"
#include "asn1.h"
#include "pkcrypt_op.h"
#include "cert.h"
#include "cmp.h"
#include "pkimessage.h"
#include "bcipher_op.h"
#include "rand_ansi.h"
#include "sha1.h"
#include "hash_op.h"

#include "keysharefs.h"
#include "pbe.h"

// from libpki
#include "CertHelper.h"
#include "KeyHistory.h"

ASNDescriptor AD_KeyHistory = 
{
   ADE_Sequence,
   {AD_Certificate, 0},
   {AD_EncryptedValue, TAG_IMPLICIT|0|ASN_OPTIONAL},
   {AD_KeyIdentifier, TAG_IMPLICIT|1|ASN_OPTIONAL},
   {AD_Certificate, TAG_IMPLICIT|2|ASN_OPTIONAL},
   {AD_Certificate, TAG_IMPLICIT|3|ASN_OPTIONAL},
   ADE_End
};

ASNDescriptor AD_KeyHistorys = 
{
  ADE_SequenceOf,
  { AD_KeyHistory, 0 },
  ADE_End
};

/**
 * 인증서 갱신 이후, 기존 키쌍을 Key History 파일에 저장한다.
 */
int KEYHIST_StorePrevKeyPair(Certificate    *oldWithOld,
                             Certificate    *oldWithNew,
                             Certificate    *newWithOld,
                             PrivateKeyInfo *prevPriKey,
                             Certificate    *newWithNew,
                             PrivateKeyInfo *newPriKey,
                             const char     *filename)
{
  int ret;
  KeyHistorys *keyHists;
  KeyHistory  *keyHist;
  ASNBuf      *bufKeyHist;
  ASNBuf      *bufPrevPriKey;

  AlgorithmIdentifier *symmAlg, *hashAlg;
  KeyIdentifier *keyIdentifier;
  Extension *extSubjectKeyId;

  ER_RET_IF(oldWithOld == NULL ||
            newWithNew == NULL);
  ER_RET_IF(filename == NULL);
  ER_RET_IF((oldWithNew == NULL) ^ (newWithOld == NULL));

  // 1. 새로운 KeyHistory 생성
  //  KeyHistory  ::= SEQUENCE {
  //    oldWithOld    Certificate,
  //    privateKey    [0] EncryptedValue OPTIONAL,
  //    keyIdentifier [1] KeyIdentifier  OPTIONAL,  -- 이 인증서 다음 인증서 내의 공개키에 대한 KeyIdentifier
  //    oldWithNew    [2] Certificate    OPTIONAL,
  //    newWithOld    [3] Certificate    OPTIONAL,
  //  -- **********
  //  -- * oldWithNew와 newWithOld는 RootCA인 경우에만 사용된다.
  //  -- * privateKey는 새로운 privateKey를 이용하여 암호화 된다.
  //  -- **********
  //  }
  keyHist = ASN_New(KeyHistory, NULL);
  ASN_Copy(keyHist->oldWithOld, oldWithOld);
  if (prevPriKey != NULL)
  {
    bufPrevPriKey  = ASN_EncodeDER(prevPriKey);
    if (bufPrevPriKey == NULL)
    {
      ASN_Del(keyHist);
      return FAIL;
    }
    ASNSeq_NewOptional(pASN(&keyHist->privateKey), ASN_SEQ(keyHist));
    symmAlg = ASN_New(AlgorithmIdentifier, NULL);
    hashAlg = ASN_New(AlgorithmIdentifier, NULL);
    AlgorithmIdentifier_SetNid(symmAlg, NID_rc2CBC, NULL);
    AlgorithmIdentifier_SetNid(hashAlg, NID_SHA1, NULL);
    if (prevPriKey->privateKeyAlgorithm->algorithm->nid == NID_rsaEncryption)
    {
      /*# NOTE : 현재는 RSA만 encryption이 가능하나 추후에 알고리즘이 추가되면 변경할 것 */
      ret = EncryptedValue_Set(keyHist->privateKey, 
                               (unsigned char*)bufPrevPriKey->data,
                               bufPrevPriKey->len,
                               NULL, DEFAULT_SYMMETRIC_KEY_LEN,
                               symmAlg,
                               newWithNew->tbsCertificate->subjectPublicKeyInfo,
                               hashAlg);
    }
    else
    {
      // RSA가 아니면 공개키 암호화를 할 수 없으므로 비공개키의 hash값을 사용한다.
      unsigned char symmKey[DEFAULT_SYMMETRIC_KEY_LEN];

      ret = CERT_MakeSymmKeyFromPK(symmKey, sizeof(symmKey), newPriKey);
      if (ret != SUCCESS)
      {
        ASN_Del(symmAlg);
        ASN_Del(hashAlg);
        ASN_Del(keyHist);
        return FAIL;
      }

      ret = EncryptedValue_Set(keyHist->privateKey,
                               (unsigned char*)bufPrevPriKey->data,
                               bufPrevPriKey->len,
                               symmKey, DEFAULT_SYMMETRIC_KEY_LEN, 
                               symmAlg,
                               NULL, 
                               hashAlg);
    }
    ASN_Del(symmAlg);
    ASN_Del(hashAlg);
    ASNBuf_Del(bufPrevPriKey);
    if (ret != SUCCESS)
    {
      ASN_Del(keyHist);
      return FAIL;
    }
  }

  extSubjectKeyId  = Extensions_GetPByNid(newWithNew->tbsCertificate->extensions, NID_subjectKeyIdentifier);
  if (extSubjectKeyId != NULL)
  {
    keyIdentifier  = Extension_GetByType(NULL, extSubjectKeyId, SubjectKeyIdentifier);
    if (keyIdentifier != NULL)
    {
      ASNSeq_NewOptional(pASN(&keyHist->keyIdentifier), ASN_SEQ(keyHist));
      ASN_Copy(keyHist->keyIdentifier, keyIdentifier);
      ASN_Del(keyIdentifier);
    }
  }

  if (oldWithNew != NULL)
  {
    ASNSeq_NewOptional(pASN(&keyHist->oldWithNew), ASN_SEQ(keyHist));
    ret = ASN_Copy(keyHist->oldWithNew, oldWithNew);
    if (ret != SUCCESS)
    {
      ASN_Del(keyHist);
      return FAIL;
    }
    ASNSeq_NewOptional(pASN(&keyHist->newWithOld), ASN_SEQ(keyHist));
    ret = ASN_Copy(keyHist->newWithOld, newWithOld);
    if (ret != SUCCESS)
    {
      ASN_Del(keyHist);
      return FAIL;
    }
  }

  // 2. 기존 KeyHistorys에 추가
  // 기존 history 파일이 존재하는지 확인
  if (access(filename, 0) == 0)
  {
    // 기존 history 파일 존재
    bufKeyHist  = ASNBuf_NewFromFile(filename);
    if (bufKeyHist == NULL)
    {
      ASN_Del(keyHist);
      return ER_KEYHIST_INVALID_KEY_HISTORY_FILE;
    }
    keyHists = ASN_New(KeyHistorys, bufKeyHist);
    ASNBuf_Del(bufKeyHist);
    if (keyHists == NULL)
    {
      ASN_Del(keyHist);
      return ER_KEYHIST_INVALID_KEY_HISTORY_FILE;
    }
  }
  else
  {
    // 기존 history 파일 존재하지 않음
    keyHists = ASN_New(KeyHistorys, NULL);
  }

  ASNSeqOf_AddP(ASN_SEQOF(keyHists), ASN(keyHist));

  // 3. 파일로 저장
  bufKeyHist = ASN_EncodeDER(keyHists);
  ASN_Del(keyHists);
  ASNBuf_SaveToFile(bufKeyHist, filename);
  ASNBuf_Del(bufKeyHist);
  return SUCCESS;
}

/**
 * Key History 파일로부터 주어진 인증서 바로 이전 인증서를 가져온다.
 */
int KEYHIST_LoadPrevCertificate(Certificate **oldWithOld,
                                Certificate **oldWithNew,
                                Certificate **newWithOld,
                                Certificate  *curCert,
                                const char   *filename)
{
  KeyHistorys *keyHists;
  ASNBuf *bufKeyHist;
  Extension *extSubjectKeyId;
  KeyIdentifier *keyIdentifier;
  int i;

  ER_RET_IF(filename == NULL);
  ER_RET_IF(oldWithOld == NULL ||
            curCert == NULL);
  
  *oldWithOld = NULL;
  if (oldWithNew != NULL)
    *oldWithNew = NULL;
  if (newWithOld != NULL)
    *newWithOld = NULL;
  
  bufKeyHist  = ASNBuf_NewFromFile(filename);
  if (bufKeyHist == NULL)
  {
    return ER_KEYHIST_FAIL_TO_OPEN_KEY_HISTORY_FILE;
  }
  
  keyHists = ASN_New(KeyHistorys, bufKeyHist);
  ASNBuf_Del(bufKeyHist);
  if (keyHists == NULL)
  {
    return ER_KEYHIST_INVALID_KEY_HISTORY_FILE;
  }

  // 주어진 인증서 이전 인증서를 찾음
  /*# NOTE: 현 구현은 KeyIdentifier가 반드시 존재하는 경우만을 처리 */
  extSubjectKeyId  = Extensions_GetPByNid(curCert->tbsCertificate->extensions, NID_subjectKeyIdentifier);
  if (extSubjectKeyId != NULL)
  {
    keyIdentifier  = Extension_GetByType(NULL, extSubjectKeyId, SubjectKeyIdentifier);
    if (keyIdentifier == NULL)
    {
      ASN_Del(keyHists);
      return FAIL;
    }
  }
  else
  {
    ASN_Del(keyHists);
    return FAIL;
  }

  for (i=0; i< keyHists->size; i++)
  {
    if (KeyIdentifier_Compare(keyHists->member[i]->keyIdentifier, keyIdentifier) == 0)
    {
      *oldWithOld = (Certificate*)ASN_Dup(ASN(keyHists->member[i]->oldWithOld));
      if (keyHists->member[i]->newWithOld != NULL && newWithOld != NULL)
        *newWithOld = (Certificate*)ASN_Dup(ASN(keyHists->member[i]->newWithOld));
      if (keyHists->member[i]->oldWithNew != NULL && oldWithNew != NULL)
        *oldWithNew = (Certificate*)ASN_Dup(ASN(keyHists->member[i]->oldWithNew));
      ASN_Del(keyHists);
      return SUCCESS;    
    }
  }

  ASN_Del(keyHists);
  return ER_KEYHIST_FAIL_TO_FIND_FROM_HISTORY_FILE;
}


/**
 * Key History 파일로부터 주어진 비공개키 바로 이전 비공개키를 가져온다.
 */
int KEYHIST_LoadPrevPrivateKey(PrivateKeyInfo **prevPriKey,
                               Certificate     *curCert,
                               PrivateKeyInfo  *curPriKey,
                               const char      *filename)
{
  KeyHistorys *keyHists;
  ASNBuf *bufKeyHist;
  Extension *extSubjectKeyId;
  KeyIdentifier *keyIdentifier;
  ASNBuf bufPriKey;
  unsigned char buf[2048];
  int buflen;
  int ret;
  int i;

  ER_RET_IF(filename == NULL);
  ER_RET_IF(prevPriKey == NULL ||
            curCert == NULL ||
            curPriKey  == NULL);
  
  *prevPriKey = NULL;
  
  bufKeyHist  = ASNBuf_NewFromFile(filename);
  if (bufKeyHist == NULL)
  {
    return ER_KEYHIST_FAIL_TO_OPEN_KEY_HISTORY_FILE;
  }
  
  keyHists = ASN_New(KeyHistorys, bufKeyHist);
  ASNBuf_Del(bufKeyHist);
  if (keyHists == NULL)
  {
    return ER_KEYHIST_INVALID_KEY_HISTORY_FILE;
  }

  // 주어진 인증서 이전 인증서를 찾음
  /*# NOTE: 현 구현은 KeyIdentifier가 반드시 존재하는 경우만을 처리 */
  extSubjectKeyId  = Extensions_GetPByNid(curCert->tbsCertificate->extensions, NID_subjectKeyIdentifier);
  if (extSubjectKeyId != NULL)
  {
    keyIdentifier  = Extension_GetByType(NULL, extSubjectKeyId, SubjectKeyIdentifier);
    if (keyIdentifier == NULL)
    {
      ASN_Del(keyHists);
      return FAIL;
    }
  }
  else
  {
    ASN_Del(keyHists);
    return FAIL;
  }

  for (i=0; i< keyHists->size; i++)
  {
    if (KeyIdentifier_Compare(keyHists->member[i]->keyIdentifier, keyIdentifier) == 0)
    {
      if (keyHists->member[i]->privateKey == NULL)
        return ER_KEYHIST_PRIKEY_NOT_EXIST;

      if (curPriKey->privateKeyAlgorithm->algorithm->nid == NID_rsaEncryption)
      {
        ret = EncryptedValue_Get(keyHists->member[i]->privateKey,
                                 curPriKey,
                                 buf, &buflen, sizeof(buf)/sizeof(buf[0]),
                                 NULL, NULL, 0, NULL);
      }
      else
      {
        unsigned char symmKey[DEFAULT_SYMMETRIC_KEY_LEN];
        ret = CERT_MakeSymmKeyFromPK(symmKey, sizeof(symmKey), curPriKey);
        if (ret != SUCCESS)
        {
          ASN_Del(keyHists);
          return ER_KEYHIST_FAIL_TO_RECOVER_PRIKEY;
        }
        ret = EncryptedValue_Get(keyHists->member[i]->privateKey,
                                 NULL, 
                                 buf, &buflen, sizeof(buf)/sizeof(buf[0]),
                                 symmKey, NULL, sizeof(symmKey), NULL);
      }
      ASN_Del(keyHists);
      if (ret != SUCCESS)
        return ER_KEYHIST_FAIL_TO_RECOVER_PRIKEY;
      
      ASNBuf_SetP(&bufPriKey, (char*)buf, buflen);
      *prevPriKey  = ASN_New(PrivateKeyInfo, &bufPriKey);
      if (*prevPriKey == NULL)
      {
        return ER_KEYHIST_FAIL_TO_RECOVER_PRIKEY;
      }
      return SUCCESS;    
    }
  }

  ASN_Del(keyHists);
  return ER_KEYHIST_FAIL_TO_FIND_FROM_HISTORY_FILE;
}
