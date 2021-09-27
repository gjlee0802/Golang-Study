/**
 * @file     CRLHelper.h
 *
 * @desc     CA 에서 인증서 폐지 목록 생성 관련 함수
 * @author   박지영(jypark@pentasecurity.com)
 * @since    2001.11.22
 *
 */

#ifndef _CRL_HELPER_H_
#define _CRL_HELPER_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * CRL Extension template값으로부터 extension값을 생성하여 CRL의 Extensions에 추가한다.
 *  - CRL Extensions
 *    AuthorityKeyIdentifier
 *    IssuerAlternativeName
 *    CRLNumber
 *    DeltaCRLIndicator
 *    IssueingDistributionPoint
 * @param *extensions    (Out) Extension을 Extensions
 * @param  crlNumber     (In)  CRL Number
 *                            (이 값이 -1 이하의 값이거나 혹은 extsTemplate에 해당 영역이 없는 경우 추가되지 않음)
 * @param *pIssuerInfo    (In)  인증서 폐지 목록 발급자 정보
 * @param  baseCrlNumber (In)  생성하는 CRL이 DeltaCRL인 경우 해당 Base CRL의 CRL Number
 * @param *extTemplate   (In)  설정할 Extension에 대한 정보를 담고 있는 Template값
 * @return
 *  - SUCCESS: 성공
 */
enum
{
  ER_MAKE_CRL_FAIL_TO_GET_ISSUER_SUBJECTKEYID= 200, /**< CRL 발급자의 인증서에서 SubjectKeyIdentifier값을 찾는데 실패 */
  ER_MAKE_CRL_INVALID_AUTHORITYKEYID,               /**< 잘못된 형식의 AuthorityKeyIdentifier
                                                      (KeyIdentifier값은 항상 지정되어야 함)
                                                      (authorityCertIssuer와 authorityCertSerialNumber는 함께 설정되어야 함) */
};

int CRL_AddExtensions(Extensions    *extensions,
                     int            crlCount,
                     Certificate   *issuerCert,
                     int            baseCrlNumber,
                     Extension     *extTemplate);

/**
 * 새로운 RevokedCertificate 값을 생성한다.
 * invalidityTime, certIssuer값은 Extension값 설정할때 사용되며,
 * 이 값들이 0이거나 혹은 extsTemplate에 해당 영역이 없는 경우 해당 Extension값은 추가되지 않는다.
 *
 * @param *serialNumber  (In) 폐지된 인증서의 시리얼 번호
 * @param  revocationTime (In) 폐지 시점
 * @param  reasonCode    (In) 폐지 사유(CRLReason)
 * @param  invalidityTime (In) InvalidityDate(0이면 추가하지 않음)
 * @param *certIssuer    (In) 폐지된 인증서를 발급한 발급자 DN
 * @param *extsTemplate  (In) 추가할 Extension에 대한 정보를 가지고 있는 Template
 *
 */
RevokedCertificate *CRL_NewRevokedCertificate(
    CertificateSerialNumber *serialNumber,
    time_t                   revocationTime,
    int                      reason,
    time_t                   invalidityTime,
    Name                    *certIssuer,
    Extensions              *extsTemplate);

#ifdef __cplusplus
}
#endif

#endif /*_CRL_HELPER_H_*/

