/**
 * @file     PriveteKeyShare.h
 *
 * @desc     CIS의 KeyShare 함수를 이용해서 비공개키를 분할하고 복원
 * @author   박지영(jypark@pentasecurity.com)
 * @since    2001.10.24
 *
 * Revision History
 *
 * @date     2002.7.16 : Start
 *           2003.9.16 : 조현래(hrcho@pentasecurity.com) 취합 및 파일 구분 정리
 *
 */


#ifndef _PRIVEKEY_SHARE_H_
#define _PRIVEKEY_SHARE_H_

#include "asn1.h"
#include "x509pkc.h"
#include "cms.h"
#include "cert.h"
#include "crl.h"
#include "cmp.h"
#include "pkimessage.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 키 분배 저장을 위한 구조체 및 타입 선언 */
typedef struct _ASNKeyShareInfo
{
  ASNSeqClass klass;
  BitString   *x;
  BitString   *y;
} ASNKeyShareInfo;
extern ASNDescriptor AD_ASNKeyShareInfo;

typedef struct _EncryptedKeyShareInfo
{
  ASNSeqClass klass;
  KeyIdentifier *keyIdentifier;
  BitString  *encryptedInfo;
} EncryptedKeyShareInfo;
extern ASNDescriptor AD_EncryptedKeyShareInfo;

typedef struct _SeqOfEncryptedKeyShareInfo
{
  ASNSeqOfClass klass;
  int size;
  EncryptedKeyShareInfo **member;
} SeqOfEncryptedKeyShareInfo;
extern ASNDescriptor AD_SeqOfEncryptedKeyShareInfo;

typedef struct _EncryptedKeyShareInfos
{
  ASNSeqClass klass;
  Integer *reqInfosNum;
  AlgorithmIdentifier *symmAlg;
  BitString *prime; /*optional [0] */
  SeqOfEncryptedKeyShareInfo *info; /* optional [1] */
} EncryptedKeyShareInfos;
extern ASNDescriptor AD_EncryptedKeyShareInfos;

typedef struct _EncryptedPrivateKey
{
  ASNSeqClass klass;
  Boolean *useSeperateStorage;
  EncryptedKeyShareInfos *keyShareInfos;
  EncryptedValue *encryptedPrivateKey; 
} EncryptedPrivateKey;
extern ASNDescriptor AD_EncryptedPrivateKey;

typedef struct _EncryptedPrivateKeyShareInfo
{
  ASNSeqClass klass;
  EncryptedKeyShareInfo *info;
  BitString *encValue;
} EncryptedPrivateKeyShareInfo;
extern ASNDescriptor AD_EncryptedPrivateKeyShareInfo;

typedef struct _SeqOfEncryptedPrivateKeyShareInfo
{
  ASNSeqOfClass klass;
  int size;
  EncryptedPrivateKeyShareInfo **member;
} SeqOfEncryptedPrivateKeyShareInfo;
extern ASNDescriptor AD_SeqOfEncryptedPrivateKeyShareInfo;

/*## 비공개키 분할/공유를 위한 비공개키 관련 함수들 ##*/
enum
{
  ER_PRIVKEY_SHARE_FAIL_TO_OPEN_PRIVATEKEYFILE = -800,
                                      /**< 비공개키 파일이 존재하지 않음 */
  ER_PRIVKEY_SHARE_INVALID_PRIVATEKEYFILE,
                                      /**< 잘못된 형식의 비공개키 파일 */
  ER_PRIVKEY_SHARE_INVALID_SYMMALG,   /**< 잘못된 형식의 symmAlg */
  ER_PRIVKEY_SHARE_INVALID_SHAREINFO, /**< 잘못된 형식의 
                                            EncryptedPrivateKeyShareInfo */
  ER_PRIVKEY_SHARE_WRONG_PASSWORD,    /**< 잘못된 패스워드 */
  ER_PRIVKEY_SHARE_WRONG_ID,          /**< 잘못된 ID */
  ER_PRIVKEY_SHARE_FAIL_TO_RECOVER_SYMMKEY,
                                      /**< 공유된 정보로부터 대칭키 복구 실패 */
  ER_PRIVKEY_SHARE_FAIL_TO_RECOVER_PRIKEY,
                                      /**< 비공개키 복구 실패 */
  ER_PRIVKEY_SHARE_WRONG_NUM_OF_SHAREINFO,
                                      /**< 잘못된 개수의 ShareInfo */
  ER_PRIVKEY_SHARE_WRONG_NUM_OF_ADMIN,/**< 잘못된 개수의 Admin */
  ER_PRIVKEY_SHARE_SHAREINFO_MISMATCH,/**< ShareInfo의 값 내의 암호화된 
                                           비공개키 값들이 일치하지 않음 */
  ER_PRIVKEY_SHARE_FAIL_TO_ENCRYPTE_VALUE,
                                      /**< 정보를 암호화 하는데 실패 */
  ER_PRIVKEY_SHARE_INSUFFICIENT_BUFFER,
                                      /**< Buffer 크기가 작음 */
  ER_PRIVKEY_SHARE_FAIL_TO_CHANGE_PASSWORD,
                                     /**< 암호 변경 실패 */   
};

/**
 * EncryptedKeyShareInfos로부터 원래의 (대칭)키값을 복구한다.
 *
 * @param *bufSymmKey         (Out) 복구된 대칭키 값을 저장할 버퍼
 * @param *lenSymmKey         (In/Out) bufSymmKey 버퍼의 길이/복구된 대칭키 길이
 * @param *encKeyShareInfos   (In)  암호화된 키 공유 정보가 보관되어 있는 
                                    EncryptedShareInfos
 * @param *pbeAlg             (In)  키 공유 정보를 암호화 하는데 사용된 
                                    PBE(Password Based Encryption)알고리즘
 * @param **ids               (In)  관리자(들)의 ID
 * @param **passwds           (In)  관리자(들)의 암호
 * @param adminNum            (In)  ids와 passwds에 저장되어 있는 ID, 
                                    Password쌍의 개수
 *
 * @return 
 *  - SUCCESS : 성공
 */
ERT KEYSHARE_DecryptKeyShareInfos(
    unsigned char          *bufSymmKey,
    int                    *lenSymmKey,
    EncryptedKeyShareInfos *encKeyShareInfos,
    AlgorithmIdentifier    *pbeAlg, 
    const char             **ids,
    const char             **passwds,
    int                    adminNum);

/**
 * 키 분배 방식을 이용하여 저장된 Authority의 비공개키를 가져온다.
 * 구체적인 과정은 다음과 같다.
 *  1. EncryptedPrivateKey내, 혹은 EncryptedPrivateKeyShareInfo내의 
 *     암호화 되어 있는 KeyShareInfo를 관리자의 암호로 복호화
 *  2. m개의 KeyShareInfo로 비공개키를 암호화 하는데 사용된 대칭키 복구
 *  3. m의 대칭키로 비공개키를 복호화
 *
 * @param **priKey            (Out) Authority 비공개키
 * @param  *encPrivateKey     (In)  암호화된 비공개키 및 복구에 필요한 
                                    정보들이 저장되어 있는 구조체
 * @param  *seqOfShareInfo    (In)  관리자 별로 별도의 저장소에 보관하는 경우,
                                    각 관리자들이 보관하고 있는 정보
 * @param **ids               (In)  관리자(들)의 ID
 * @param **passwds           (In)  관리자(들)의 암호
 * @param   adminNum          (In)  ids, passwds에 전달된 ID, 암호 쌍의 개수
 * @return
 *  - SUCCESS : 성공
 */
ERT KEYSHARE_RecoverPrivateKey(
    PrivateKeyInfo                    **privKey,
    EncryptedPrivateKey               *encPrivateKey,
    SeqOfEncryptedPrivateKeyShareInfo *seqOfShareInfo,
    const char                        **ids, 
    const char                        **passwds,
    int                               adminNum);

/**
 * Authority 비공개키를 복호화 화는데 필요한 최소 관리자 수를 얻는다.
 *
 * @param *reqNum     (Out) 필요한 관리자 수
 * @param *filePath   (In)  키 공유에 대한 정보가 저장되어 있는 파일 이름
 *
 * @return
 *  - SUCCESS : 성공
 *  - 그외     : 실패
 */
ERT KEYSHARE_GetReqInfosNum(int *reqNum, const char *filePath);

#ifdef __cplusplus
}
#endif

#endif /* _PRIVEKEY_SHARE_H_ */
