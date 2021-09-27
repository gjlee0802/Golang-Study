/**
 * @file     CertHelper.h
 *
 * @desc     인증서 생성 관련 CIS wrapper 함수
 * @author   박지영(jypark@pentasecurity.com)
 * @since    2001.11.16
 *
 * Revision History
 *
 * @date     2002.7.16 : Start
 *           2009.9.16 : 조현래(hrcho@pentasecurity.com) 취합 및 파일 구분 정리
 *
 */

#ifndef _CERT_HELPER_H_
#define _CERT_HELPER_H_

#include "pkiinfo.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 인증서를 생성한다.
 * @param *newCert       (Out) 생성된 인증서
 * @param *entityInfo    (In)  사용자 정보
 * @param *reqCertInfo   (In)  인증서를 발급할 키에 대한 정보
                               (public키 값은 반드시 있어야 함)
 * @param *policyInfo    (In)  인증서 정책 정보
 * @param *issuerInfo    (In)  인증서 발급자 정보
 * @return
 *  - SUCCESS : 성공
 * @see PKIEntityInfo_Set
 * @see PKIPolicyInfo_Set
 * @see PKIIssuerInfo_Set
 */
enum
{
  ER_MAKE_CERT_INVALID_VALIDITY  = 200,         /**< 잘못된 유효기간 */
  ER_MAKE_CERT_INVALID_PRIVATEKEYUSAGEPERIOD,   /**< 잘못된 
                      PrivateKeyUsagePeriod값(notAfter가 notBefore보다 작음) */
  ER_MAKE_CERT_FAIL_TO_GET_ISSUER_SUBJECTKEYID, /**< CA의 인증서에서 
                      SubjectKeyIdentifier값을 찾는데 실패 */
  ER_MAKE_CERT_INVALID_AUTHORITYKEYID,          /**< 잘못된 형식의 
                      AuthorityKeyIdentifier (KeyIdentifier값은 항상 
                      지정되어야 함) (authorityCertIssuer와 
                      authorityCertSerialNumber는 함께 설정되어야 함) */
};

int CERT_MakeCertificate(Certificate *newCert,
    PKIEntityInfo  *entityInfo,
    PKIReqCertInfo *reqCertInfo,
    PKIPolicyInfo  *policyInfo,
    PKIIssuerInfo  *issuerInfo,
    const char     *cdpUri);
/**
 * Extension template값으로부터 extension값을 생성하여 Extensions에 추가한다.
 *
 * @param *pExtensions    (In,Out)  Extensions이 추가될 인증서 값
 * @param *extTemplate   (In)  설정할 Extension에 대한 정보를 담고 있는 Template
 * @param *entityInfo    (In)  사용자 정보
 * @param *reqCertInfo   (In)  인증서를 발급할 키에 대한 정보
                               (public키 값은 반드시 있어야 함)
 * @param *issuerInfo    (In)  인증서 발급자 정보
 * @param *cdpUri        (In)  CDP URI, 정책단위로 설정되는 것이 기본이나 이 
 *                             파라미터를 통해 오버라이드 할 수 있다.
 *                             파티션드 씨알엘에 쓰인다.
 */
int CERT_AddCertExtensions(Certificate *newCert,
    Extension *extTemplate,
    PKIEntityInfo *entityInfo,
    PKIReqCertInfo *reqCertInfo,
    PKIIssuerInfo *issuerInfo, 
    const char *cdpUri);

/**
 * 비공개키를 hash하여 대칭키를 생성한다.
 * 
 * @param bufSymmKey (Out) 생성된 대칭키
 * @param lenSymmKey (In)  생성할 대칭키의 길이
 * @param priKey     (In)  비공개키
 */
ERT CERT_MakeSymmKeyFromPK(
    unsigned char  *bufSymmKey, 
    int             lenSymmKey, 
    PrivateKeyInfo *priKey);

/**
 * 공개키의 길이(bit)를 구한다. 
 * 이 함수에서 구하는 공개키의 길이는 공개키 데이터의 bit수를 의미하며 
 * 최상위 bit가 1이 아닐 수도 있다.
 * 공개키의 길이는 128단위로 반올림 한 값을 리턴
 *
 * @param *lenKeyBit  (Out) 공개키 길이
 * @param *pubKey     (In)  길이를 구하려는 공개키
 *
 * @return 
 *  - SUCCESS : 성공
 */
enum {
  ER_CERT_INVALID_PUBLICKEYINFO = -600,  
                                        /**< 잘못된 형식의 PublicKeyInfo */
  ER_CERT_UNKNOWN_PUBLICKEY_ALG,
                                        /**< 알수 없는 공개키 알고리즘 */
};
ERT CERT_GetKeyBitLength(int *lenKeyBit, PublicKeyInfo *pubKey);

#ifdef __cplusplus
}
#endif

#endif /*_CERT_HELPER_H_*/

