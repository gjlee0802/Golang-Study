/**
 * @file     KeyHistory.h
 *
 * @desc     Key History 처리 함수들
 * @author   조현래 (hrcho@pentasecurity.com)
 * @since    2003.07.18
 *
 */

#ifndef _KEY_HISTORY
#define _KEY_HISTORY

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _KeyHistory
{
  ASNSeqClass klass;
  Certificate *oldWithOld;
  EncryptedValue *privateKey;     /* optional [0] */
  KeyIdentifier *keyIdentifier;   /* optional [1] */
  Certificate *oldWithNew;        /* optional [2] */
  Certificate *newWithOld;        /* optional [3] */
} KeyHistory;

typedef struct _KeyHistorys
{
  ASNSeqOfClass klass;
  int size;
  KeyHistory **member;
} KeyHistorys;

enum
{
  ER_KEYHIST_INVALID_KEY_HISTORY_FILE = -900, /**< 잘못된 형식의 Key History 파일 */
  ER_KEYHIST_FAIL_TO_OPEN_KEY_HISTORY_FILE,   /**< Key History 파일 열기 실패 */
  ER_KEYHIST_FAIL_TO_FIND_FROM_HISTORY_FILE,  /**< Key History 파일에서 찾기 실패 */
  ER_KEYHIST_PRIKEY_NOT_EXIST,                /**< Key History 파일 안에 구하려는 비공개키가 들어있지 않음 */
  ER_KEYHIST_FAIL_TO_RECOVER_PRIKEY           /**< 비공개키 복구 실패 */
};

/**
 * 인증서 갱신 이후, 기존 키쌍을 Key History 파일에 저장한다.
 *
 * @param *oldWithOld (In) 기존 인증서
 * @param *oldWithNew (In) 새로운 비공개키를 이용하여 기존의 공개키에 대해 발급한 인증서(NULL이면 저장하지 않음)
 * @param *newWithOld (In) 기존의 비공개키를 이용하여 새로운 공개키에 대해 발급한 인증서(NULL이면 저장하지 않음)
 * @param *prevPriKey (In) Key History 파일에 저장할 비공개키(NULL이면 인증서만을 저장)
 * @param *newWithNew (In) 새로운 인증서
 * @param *filename   (In) History 파일 이름
 *
 * @return 
 *  - SUCCESS : 성공
 */
int KEYHIST_StorePrevKeyPair(Certificate    *oldWithOld,
                             Certificate    *oldWithNew,
                             Certificate    *newWithOld,
                             PrivateKeyInfo *prevPriKey,
                             Certificate    *newWithNew,
                             PrivateKeyInfo *newPriKey,
                             const char     *filename);

/**
 * Key History 파일로부터 주어진 인증서 바로 이전 인증서를 가져온다.
 *
 * @param **oldWithOld (Out) 기존 인증서
 * @param **oldWithNew (Out) 새로운 비공개키를 이용하여 기존의 공개키에 대해 발급한 인증서(NULL이면 저장하지 않음)
 * @param **newWithOld (Out) 기존의 비공개키를 이용하여 새로운 공개키에 대해 발급한 인증서(NULL이면 저장하지 않음)
 * @param *curCert     (In)  찾으려는 인증서 바로 이후에 발급된 인증서
 * @param *filename    (In)  History 파일 이름
 *
 * @return 
 *  - SUCCESS : 성공
 *  - ER_KEYHIST_FAIL_TO_OPEN_KEY_HISTORY_FILE
 *  - ER_KEYHIST_INVALID_KEY_HISTORY_FILE
 *  - ER_KEYHIST_FAIL_TO_FIND_FROM_HISTORY_FILE
 *  - FAIL
 */
int KEYHIST_LoadPrevCertificate(Certificate **oldWithOld,
                                Certificate **oldWithNew,
                                Certificate **newWithOld,
                                Certificate  *curCert,
                                const char   *filename);


/**
 * Key History 파일로부터 주어진 비공개키 바로 이전 비공개키를 가져온다.
 *
 * @param *prevPriKey  (In) 기존 비공개키
 * @param *curCert     (In) 찾으려는 비공개키 바로 이후에 발급된 인증서
 * @param *curPriKey   (In) 찾으려는 비공개키 바로 이후에 생성된 비공개키(암호화 되어 있는 키 복호화에 사용됨)
 * @param *filename    (In) History 파일 이름
 *
 * @return 
 *  - SUCCESS : 성공
 *  - ER_KEYHIST_FAIL_TO_OPEN_KEY_HISTORY_FILE
 *  - ER_KEYHIST_INVALID_KEY_HISTORY_FILE
 *  - ER_KEYHIST_FAIL_TO_RECOVER_PRIKEY
 *  - ER_KEYHIST_FAIL_TO_FIND_FROM_HISTORY_FILE
 *  - FAIL
 */
int KEYHIST_LoadPrevPrivateKey(PrivateKeyInfo **prevPriKey,
                               Certificate     *curCert,
                               PrivateKeyInfo  *curPriKey,
                               const char      *filename);

#ifdef __cplusplus
}
#endif

#endif /* _KEY_HISTORY */

