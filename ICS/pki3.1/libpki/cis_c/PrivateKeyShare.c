/**
 * @file     PrivateKeyShare.c
 *
 * @desc     인증서와 비공개키 관련 CIS wrapping functions
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2003.7.16
 *
 * Revision History
 *
 * @date     2003.7.16 : Start
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
#include <signal.h>
#include <errno.h> 
#endif

// CIS headers
#include "base_define.h"
#include "asn1.h"
#include "pkcrypt_op.h"
#include "bcipher_op.h"
#include "rand_ansi.h"
#include "sha1.h"
#include "x509pkc.h"
#include "cmp_types.h"

#include "keysharefs.h"
#include "pbe.h"

// libpki
#include "PrivateKeyShare.h"
#include "er_define.h"

ASNDescriptor AD_EncryptedPrivateKey = 
{
   ADE_Sequence,
   {AD_Boolean, 0},
   {AD_EncryptedKeyShareInfos, 0},
   {AD_EncryptedValue, 0},
   ADE_End
};

ASNDescriptor AD_EncryptedKeyShareInfos = 
{
   ADE_Sequence,
   {AD_Integer, 0},
   {AD_AlgorithmIdentifier, 0},
   {AD_BitString, TAG_IMPLICIT|0|ASN_OPTIONAL},
   {AD_SeqOfEncryptedKeyShareInfo, TAG_IMPLICIT|1|ASN_OPTIONAL},
   ADE_End
};

ASNDescriptor AD_SeqOfEncryptedKeyShareInfo = 
{
  ADE_SequenceOf,
  { AD_EncryptedKeyShareInfo, 0 },
  ADE_End
};

ASNDescriptor AD_EncryptedKeyShareInfo = 
{
   ADE_Sequence,
   {AD_KeyIdentifier, 0},
   {AD_BitString, 0},
   ADE_End
};

ASNDescriptor AD_SeqOfEncryptedPrivateKeyShareInfo = 
{
  ADE_SequenceOf,
  { AD_EncryptedPrivateKeyShareInfo, 0 },
  ADE_End
};

ASNDescriptor AD_EncryptedPrivateKeyShareInfo = 
{
   ADE_Sequence,
   {AD_EncryptedKeyShareInfo, 0},
   {AD_BitString, 0},
   ADE_End
};

ASNDescriptor AD_ASNKeyShareInfo = 
{
   ADE_Sequence,
   { AD_BitString, 0 },
   { AD_BitString, 0 },
   ADE_End
};


/**
 * 비공개키를 복호화 화는데 필요한 최소 관리자 수를 얻는다.
 */
ERT KEYSHARE_GetReqInfosNum(int *reqNum, const char *filename)
{
  EncryptedPrivateKey *encPrivateKey;
  ASNBuf  *encPrivateKeyBuf;
  int ret;

  ER_RET_IF(reqNum == NULL);

  encPrivateKeyBuf = ASNBuf_NewFromFile(filename);
  ER_RET_VAL_IF((encPrivateKeyBuf == NULL), ER_PRIVKEY_SHARE_FAIL_TO_OPEN_PRIVATEKEYFILE);

  encPrivateKey = ASN_New(EncryptedPrivateKey, encPrivateKeyBuf);
  ASNBuf_Del(encPrivateKeyBuf);

  ER_RET_VAL_IF((encPrivateKey == NULL), ER_PRIVKEY_SHARE_INVALID_PRIVATEKEYFILE);

  ret = ASNInt_GetInt(reqNum, encPrivateKey->keyShareInfos->reqInfosNum);
  ASN_Del(encPrivateKey);

  return ret;
}

/**
 *  EncryptedKeyShareInfos로부터 원래의 키값을 복구한다.
 */
ERT KEYSHARE_DecryptKeyShareInfos(
    unsigned char          *bufSymmKey,
    int                    *lenSymmKey,
    EncryptedKeyShareInfos *encKeyShareInfos,
    AlgorithmIdentifier    *pbeAlg, 
    const char             **ids,
    const char             **passwds,
    int                    adminNum)
{
  int ret;
  int reqNum;
  PBEContext pbeCtx;
  ASNBuf *bufPbeParams;
  unsigned char symmKey[64];
  int keylen;

  unsigned char buf[256];
  int buflen;
  ASNBuf *bufEncInfo;
  ASNBuf *bufKeyShareInfo;
  
  ASNKeyShareInfo *keyShareInfo;
  KeyShareInfos keyShareInfos;
  
  int i, j;
  int success;

  ER_RET_IF(bufSymmKey == NULL ||
            lenSymmKey == NULL);
  ER_RET_IF(encKeyShareInfos == NULL ||
            pbeAlg == NULL ||
            pbeAlg->parameters == NULL);
  ER_RET_IF(ids == NULL ||
            passwds == NULL);
  ER_RET_IF(adminNum < 1);

  ASNInt_GetInt(&reqNum, encKeyShareInfos->reqInfosNum);

  ER_RET_VAL_IF((adminNum < reqNum), ER_PRIVKEY_SHARE_WRONG_NUM_OF_ADMIN);

  ER_RET_VAL_IF((ASNAny_Get(&bufPbeParams, pbeAlg->parameters) < 0), 
    ER_PRIVKEY_SHARE_INVALID_SYMMALG);
  
  // 1. EncryptedPrivateKey내의 암호화 되어 있는 KeyShareInfo를 
  // 관리자의 암호로 복호화
  switch (reqNum)
  {
  case 1:
    success = 0;
    for (j = 0; j < encKeyShareInfos->info->size; j++)
    {
      ASNStr_Get(buf, sizeof(buf)/sizeof(buf[0]), 
                 encKeyShareInfos->info->member[j]->keyIdentifier);
      if (strcmp(buf, ids[0]) == 0)
      {
        PBE_Initialize(&pbeCtx, 
                       pbeAlg->algorithm->nid,
                       bufPbeParams, 
                       (const BYTE*)passwds[0]);
        bufPbeParams->index  = 0;  /* reset buffer */
        bufEncInfo
          = ASNBitStr_GetASNBuf(encKeyShareInfos->info->member[j]->
          encryptedInfo);

        ret = PBE_Decrypt(
          symmKey, (BWT *)(&keylen), 
          (BYTE *)(bufEncInfo->data),
          bufEncInfo->len, &pbeCtx);
        ASNBuf_Del(bufEncInfo);

        ER_RETX_VAL_IF((ret != SUCCESS), ER_PRIVKEY_SHARE_WRONG_PASSWORD, 
          ASNBuf_Del(bufPbeParams));

        success = 1;
        ASNBuf_Del(bufPbeParams);
        break;
      }
    }
    ER_RET_VAL_IF(!success, ER_PRIVKEY_SHARE_WRONG_ID);

    break;
  case 2:
  case 3:
    keyShareInfos.size = 0;
    for (i = 0; i< adminNum; i++)
    {
      for (j = 0; j< encKeyShareInfos->info->size; j++)
      {
        ASNStr_Get(buf, sizeof(buf)/sizeof(buf[0]), 
                   encKeyShareInfos->info->member[j]->keyIdentifier);
        if (strcmp(buf, ids[i]) == 0) 
        {
          PBE_Initialize(&pbeCtx, 
                         pbeAlg->algorithm->nid, 
                         bufPbeParams, 
                         (const BYTE *)(passwds[i]));
          bufPbeParams->index  = 0;  /* reset buffer */
        
          bufEncInfo  
            = ASNBitStr_GetASNBuf(encKeyShareInfos->info->member[j]->
            encryptedInfo);

          ret = PBE_Decrypt(
            buf, (BWT *)(&buflen), 
            (BYTE *)(bufEncInfo->data),
            bufEncInfo->len, &pbeCtx);
          ASNBuf_Del(bufEncInfo);
          ER_RETX_VAL_IF((ret != SUCCESS), ER_PRIVKEY_SHARE_WRONG_PASSWORD, 
            ASNBuf_Del(bufPbeParams));

          bufKeyShareInfo  = ASNBuf_New(buflen);
          ASNBuf_Set(bufKeyShareInfo, buf, buflen);

          keyShareInfo = ASN_New(ASNKeyShareInfo, bufKeyShareInfo);
          ASNBuf_Del(bufKeyShareInfo);

          ER_RETX_VAL_IF((keyShareInfo == NULL), ER_PRIVKEY_SHARE_WRONG_PASSWORD, 
            ASNBuf_Del(bufPbeParams));

          buflen = ASNBitStr_Get(
            (char *)(buf), sizeof(buf),
            keyShareInfo->x);
          buflen /= 8;
          MINT_ReadFromBuffer(&keyShareInfos.info[i].x, buf, buflen);
          buflen = ASNBitStr_Get(
            (char *)(buf), sizeof(buf),
            keyShareInfo->y);
          buflen /= 8;
          MINT_ReadFromBuffer(&keyShareInfos.info[i].y, buf, buflen);
          ASN_Del(keyShareInfo);
        
          keyShareInfos.size++;
          break;
        }
      }
    }
    ASNBuf_Del(bufPbeParams);

    buflen = ASNBitStr_Get(
      (char *)(buf), sizeof(buf),
      encKeyShareInfos->prime);
    buflen /= 8;
    MINT_ReadFromBuffer(&keyShareInfos.prime, buf, buflen);

    ER_RET_VAL_IF((keyShareInfos.size < reqNum), ER_PRIVKEY_SHARE_WRONG_ID);
  
    // 3. m개의 KeyShareInfo로 비공개키를 암호화 하는데 사용된 대칭키 복구
    if (reqNum == 2)
      ret = KEYSHAREFS_Recover2SharedInfo(
        symmKey, (BWT *)(&keylen), &keyShareInfos);
    else
      ret = KEYSHAREFS_Recover3SharedInfo(
        symmKey, (BWT *)(&keylen), &keyShareInfos);

    ER_RET_VAL_IF((ret != SUCCESS), ER_PRIVKEY_SHARE_FAIL_TO_RECOVER_SYMMKEY);

    break;
  default:
    return ER_PRIVKEY_SHARE_INVALID_PRIVATEKEYFILE;
  }
  
  ER_RET_VAL_IF((keylen < keylen), ER_PRIVKEY_SHARE_INSUFFICIENT_BUFFER);

  memcpy(bufSymmKey, symmKey, keylen);
  *lenSymmKey = keylen;

  return SUCCESS;
}

/**
 * 키 분배 방식을 이용하여 저장된 Authority의 비공개키를 가져온다.
 * 구체적인 과정은 다음과 같다.
 *   1. EncryptedPrivateKey내, 혹은 EncryptedPrivateKeyShareInfo내의 
 *      암호화 되어 있는 KeyShareInfo를 관리자의 암호로 복호화
 *   2. m개의 KeyShareInfo로 비공개키를 암호화 하는데 사용된 대칭키 복구
 *   3. m의 대칭키로 비공개키를 복호화
 */
ERT KEYSHARE_RecoverPrivateKey(
    PrivateKeyInfo                    **privKey,
    EncryptedPrivateKey               *encPrivateKey,
    SeqOfEncryptedPrivateKeyShareInfo *seqOfShareInfo,
    const char                        **ids, 
    const char                        **passwds,
    int                               adminNum)
{
  int ret;
  int i;
  EncryptedKeyShareInfos *keyShareInfo;
  EncryptedValue *encVal;
  unsigned char symmKey[64];
  int           keylen;

  ASNBuf  bufPrivateKey;

  unsigned char buf[2048];
  int           buflen;

  ER_RET_IF(privKey == NULL);
  ER_RET_IF(ids == NULL || passwds == NULL);
  ER_RET_IF(encPrivateKey == NULL);

  // 초기화
  *privKey = NULL;

  encVal = ASN_New(EncryptedValue, NULL);
  ASN_Copy(encVal, encPrivateKey->encryptedPrivateKey);

  // 1. SeqOfEncryptedPrivateKeyShareInfo와 EncryptedPrivateKey값으로부터 필요한 정보 생성
  keyShareInfo = (EncryptedKeyShareInfos*)ASN_Dup(ASN(encPrivateKey->
    keyShareInfos));
  if (ASNBool_Get(encPrivateKey->useSeperateStorage))
  {
    ER_RETX_IF( seqOfShareInfo == NULL, (ASN_Del(encVal), 
      ASN_Del(keyShareInfo)) );

    ASNSeq_NewOptional(pASN(&keyShareInfo->info), ASN_SEQ(keyShareInfo));
    for (i = 0; i < seqOfShareInfo->size; i++)
    {
      if (i == 0)
      {
        ASN_Copy(encVal->encValue, seqOfShareInfo->member[i]->encValue);
      }
      else
      {
        // encValue 값 비교
        ER_RETX_VAL_IF( (encVal->encValue->len !=
          seqOfShareInfo->member[i]->encValue->len), 
          ER_PRIVKEY_SHARE_SHAREINFO_MISMATCH, 
          (ASN_Del(encVal), ASN_Del(keyShareInfo)) );

        ER_RETX_VAL_IF( (memcmp(encVal->encValue->data, 
          seqOfShareInfo->member[i]->encValue->data, 
          seqOfShareInfo->member[i]->encValue->len) != 0), 
          ER_PRIVKEY_SHARE_SHAREINFO_MISMATCH, 
          (ASN_Del(encVal), ASN_Del(keyShareInfo)) );
      }
      ASNSeqOf_Add(ASN_SEQOF(keyShareInfo->info), 
        ASN(seqOfShareInfo->member[i]->info));
    }
  }

  // 2. EncryptedPrivateKey내의 암호화 되어 있는 KeyShareInfo를 관리자의 
  // 암호로 복호화하여 비공개키를 암호화 하는데 사용된 대칭키 값을 얻음
  keylen = sizeof(symmKey);
  ret = KEYSHARE_DecryptKeyShareInfos(symmKey, &keylen, keyShareInfo, 
      encPrivateKey->keyShareInfos->symmAlg,
      ids, passwds, adminNum);
  ASN_Del(keyShareInfo);
  ER_RETX_VAL_IF( (ret != SUCCESS), ret, ASN_Del(encVal) );
  
  // 4. 3의 대칭키로 비공개키를 복호화
  ret = EncryptedValue_Get(encVal, 
                           NULL, 
                           buf, &buflen, sizeof(buf),
                           symmKey, 0, keylen,
                           NULL);
  ASN_Del(encVal);
  ER_RET_VAL_IF((ret != SUCCESS), ER_PRIVKEY_SHARE_FAIL_TO_RECOVER_PRIKEY);

  ASNBuf_SetP(&bufPrivateKey, (char *)(buf), buflen);
  *privKey = ASN_New(PrivateKeyInfo, &bufPrivateKey);
  
  ER_RET_VAL_IF((*privKey == NULL), ER_PRIVKEY_SHARE_FAIL_TO_RECOVER_PRIKEY);

  return SUCCESS;
}
