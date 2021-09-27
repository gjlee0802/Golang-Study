#ifndef _LICENSE_H_
#define _LICENSE_H_

/***********************************************************
***                                                      ***
***                                                      ***
***                   LICENSE Ver 2.0                    ***
***                              2002/1/14               ***
***                                                      ***
***********************************************************/

/** @defgroup LICENSE
    @brief  License 인증서 검증을 위한 모듈

    펜타시큐리티시스템(주)에서 사용하는 제품 라이센스와 관련된 기능들의
    그룹이다.

    주의사항
    
      1) cis를 기반으로 하여 만들어진 함수들이므로 반드시 cis와 link시켜야 한다.
      2) 이 모듈은 동적으로 로딩하지 말고 "해당 응용프로그램의 소스에 넣어 사용할
        것"을 권한다. 또한 link시 반드시 응용 프로그램 레벨에서 link하여 여러 군데
        에서 사용할 경우 생길 수 있는 충돌을 방지한다. 
        예를 들어,
          응용 프로그램 A, B, C를 만드는데 각각 사용되는 모듈이 a, b, c이며 이들의 
          관계가
             cis -> a, b, A, B, C
             a -> b
             a -> A, B 
             b -> A, B, C
             c -> A, C
          라면, license 모듈은 각각의 A, B, C에 직접 static link되어야 한다. 
*/

/** @file license.h
    @ingroup LICENSE
    @brief License 인증서 검증을 위한 모듈

    펜타시큐리티시스템(주)에서 사용하는 제품 라이센스 Root CA의 인증서
    값이 들어 있으며, 이 CA가 발급한 제품 라이센스 인증서를 검증하고 키
    쌍을 검증할 수 있는 method를 제공한다.

    Variables:
      LicenseRootCACertificateData[]
      LicenseRootCACertificateLen

    Methods:
      LICENSE_CheckKeyPair
      LICENSE_CheckCertificate
*/

#ifdef __cplusplus
extern "C" {
#endif

/** @ingroup LICENSE
    @brief 라이센스 Root CA 인증서의 길이

    펜타시큐리티시스템(주)의 제품 라이센스 Root CA 인증서의 길이
*/
extern int  LicenseRootCACertificateLen;

/** @ingroup LICENSE
    @brief 라이센스 Root CA 인증서 데이터

    펜타시큐리티시스템(주)의 제품 라이센스 Root CA 인증서 데이터
*/
extern char LicenseRootCACertificateData[];

/* 
   Error code in LICENSE group
*/

#define ER_LICENSE_CANNOT_LOAD_PRIKEY       -1
#define ER_LICENSE_CANNOT_DECODE_PRIKEY     -2
#define ER_LICENSE_CANNOT_LOAD_CERT         -3
#define ER_LICENSE_INVALID_KEYPAIR          -4
#define ER_LICENSE_CANNOT_LOAD_ROOTCERT     -5
#define ER_LICENSE_INVALID_VALIDITYPERIOD   -6
#define ER_LICENSE_INVALID_SUBJECTNAME      -7
#define ER_LICENSE_INVALID_VERIFYSTRING     -8
#define ER_LICENSE_INVALID_HOST             -9
#define ER_WINSOCK_VERSION_UNSUPPORTED      -10
#define ER_LICENSE_INVALID_CERTIFICATE      -11

/**
 * 라이센스 인증서안의 공개키와 라이센스 비공개키가 키쌍이 맞는지 확인한다.
 *
 * @param *keyPath  (In) 라이센스 키의 Full Path
 * @param *cerPath  (In) 라이센스 인증서의 Full Path
 *
 * @return 
 *  - SUCCESS : 성공
 *  - 그외    : 실패
 */
int LICENSE_CheckKeyPair(const char *keyPath, const char *cerPath);

/**
 * 제품 라이센스 인증서가 올바른지 검사한 후 (올바른 Root CA가 발급한 것인지,
 * 유효기간은 올바른지 등) 인증서안의 제품 이름이 설치된 제품의 이름(verifyString)
 * 과 같은지, 그리고 인증서안의 Host의 IP가 설치된 서버의 IP와 일치하는지 검사한다.
 *
 * @param *license_type (Out) 라이센스가 인증되면 라이센스 인증서에 들어있는 license type 내용을 내보낸다. 입력 포인터에는 256byte이 allocate되어있어야 안전하다.
 * @param *cerPath      (In) 라이센스 인증서의 Full Path
 * @param *verifyString (In) 제품 이름 (아래에 정의)
 *
 * @return 
 *  - SUCCESS : 성공
 *  - 그외    : 실패
 */
int LICENSE_CheckCertificate(char *license_type,
                             const char *cerPath, const char *verifyString);

/*
  제품 이름 : 각자 정의하여 사용할 것
*/
#define LICENSE_ISSACPKI_CA_2_2     "ISSAC CA Ver 2.2"
#define LICENSE_ISSACPKI_RA_2_2     "ISSAC RA Ver 2.2"
#define LICENSE_ISSACPKI_CA_2_3     "ISSAC CA Ver 2.3"
#define LICENSE_ISSACPKI_RA_2_3     "ISSAC RA Ver 2.3"
#define LICENSE_ISSACPKI_CA_3_0     "ISSAC CA Ver 3.0"
#define LICENSE_ISSACPKI_RA_3_0     "ISSAC RA Ver 3.0"
#define LICENSE_ISSACVA_1_0         "ISSAC VA Ver 1.0"
#define LICENSE_SECUREEXCHANGER_1_2 "Secure Exchanger Ver 1.2"
#define LICENSE_ISSACWEB_PRO_2_0    "ISSAC-Web Pro Ver 2.0"
#define LICENSE_ISSACWEB_EXPRESS_1_0 "ISSAC-Web Express Ver 1.0"

#ifdef __cplusplus
}
#endif

#endif /* _LICENSE_H_ */
