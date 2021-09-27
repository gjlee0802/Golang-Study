#ifndef _CMP_STATUS_STRING_RA_HPP_
#define _CMP_STATUS_STRING_RA_HPP_

/**
 * @file     CMPStatusStringRA.hpp
 *
 * @desc     RA에서 CMP를 통해 전달하게 되는 에러 메시지들 정의
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2001.11.15
 *
 */

/*## ErrorCodes ##*/
enum
{
  ER_RA_FAIL_TO_MAKE_REQUEST_MESSAGE = -20000,
  ER_RA_CERTTMPL_INVALID_VERSION,   /**< 인증서 요청 메시지의 certTemplate내의 version값이 잘못되었음 */
  ER_RA_CERTTMPL_INVALID_ISSUER,    /**< 인증서 요청 메시지의 certTemplate내의 issuer값이 잘못되었음 */
  ER_RA_CERTTMPL_INVALID_SUBJECT,   /**< 인증서 요청 메시지의 certTemplate내의 subject값이 잘못되었음 */
  ER_RA_CERTTMPL_INVALID_SIGNALG,   /**< 인증서 요청 메시지의 certTemplate내의 signingAlg값이 잘못되었음 */
  ER_RA_FAIL_TO_VERIFY_POP,         /**< 비공개키의 POP(Proof of possesion) 검증 실패 */
  ER_RA_INVALID_CERTREQMSG,         /**< 인증서 요청 메시지의 CertReqMsg 값이 잘못되었음 */
  ER_RA_BAD_KEYPOLICY_ID,           /**< 잘못된 Key policy ID */
  ER_RA_BAD_CERTID,                 /**< 잘못된 CertId 값 */
  ER_RA_INCORRECT_NUM_OF_CERTREQ,   /**< 발급을 요청하는 인증서의 개수가 사용자에게 설정되어 있는 개수가 일치하지 않음 */
  ER_RA_WRONG_PUBLICKEY_ALG,        /**< 공개키 알고리즘이 설정값과 일치하지 않음 */
  ER_RA_WRONG_PUBLICKEY_LEN,        /**< 공개키 길이가 설정값과 일치하지 않음 */
  ER_RA_WRONG_DOMAINPARAM,          /**< 공개키 알고리즘 내의 도메인 파라메터 값이 설정값과 일치하지 않음 */
  ER_RA_FAIL_TO_CHECK_POLICY,       /**< 인증서 요청 메시지가 사용자 정책과 일치하지 않음 */
  ER_RA_FAIL_TO_CONNECT_CA,         /**< CA에 접속 실패 */
  ER_RA_FAIL_TO_SEND_REQUEST_TO_CA, /**< CA로의 요청 메시지 전송 실패 */
  ER_RA_FAIL_TO_RECV_REPONSE_FROM_CA, /**< CA로부터 응답 메시지 수신 실패 */
  ER_RA_ERROR_MESSAGE_FROM_CA,      /**< CA로부터 에러 메시지 수신 */
  ER_RA_INVALID_MESSAGE_FROM_CA,    /**< CA로부터 잘못된 메시지 수신 */
  ER_RA_CERT_ISSUE_REJECTED_BY_CA,  /**< CA로부터 인증서 발급 받는데 실패 */
  ER_RA_FAIL_TO_SEND_CONF_TO_CA,    /**< CA로 CONFIRM 메시지 전송 실패 */
};

/*## ErrorDetails ##*/
#define RA_ERRORDETAILS_CERTTMPL_INVALID_VERSION     "인증서 요청 메시지의 certTemplate내의 version값이 잘못되었음"
#define RA_ERRORDETAILS_CERTTMPL_INVALID_ISSUER      "인증서 요청 메시지의 certTemplate내의 issuer값이 잘못되었음"
#define RA_ERRORDETAILS_CERTTMPL_INVALID_SUBJECT     "인증서 요청 메시지의 certTemplate내의 subject값이 잘못되었음"
#define RA_ERRORDETAILS_CERTTMPL_INVALID_SIGNALG     "인증서 요청 메시지의 certTemplate내의 signingAlg값이 잘못되었음"
#define RA_ERRORDETAILS_FAIL_TO_VERIFY_POP            "비공개키의 POP(Proof of possesion) 검증 실패"
#define RA_ERRORDETAILS_INVALID_CERTREQMSG            "인증서 요청 메시지의 CertReqMsg 값이 잘못되었음"
#define RA_ERRORDETAILS_BAD_KEYPOLICY_ID              "잘못된 Key policy ID"
#define RA_ERRORDETAILS_BAD_CERTID                    "잘못된 CertId 값"
#define RA_ERRORDETAILS_INCORRECT_NUM_OF_CERTREQ      "발급을 요청하는 인증서의 개수가 사용자에게 설정되어 있는 개수가 일치하지 않음"
#define RA_ERRORDETAILS_WRONG_PUBLICKEY_ALG           "공개키 알고리즘이 설정값과 일치하지 않음"
#define RA_ERRORDETAILS_WRONG_PUBLICKEY_LEN           "공개키 길이가 설정값과 일치하지 않음"
#define RA_ERRORDETAILS_WRONG_DOMAINPARAM             "공개키 알고리즘 내의 도메인 파라메터 값이 설정값과 일치하지 않음"
#define RA_ERRORDETAILS_FAIL_TO_CHECK_POLICY          "인증서 요청 메시지가 사용자 정책과 일치하지 않음"
#define RA_ERRORDETAILS_FAIL_TO_MAKE_REQUEST_MESSAGE  "CA로의 요청 PKIMessage 생성 실패"
#define RA_ERRORDETAILS_FAIL_TO_CONNECT_CA            "CA 접속 실패"
#define RA_ERRORDETAILS_FAIL_TO_SEND_REQUEST_TO_CA    "CA로의 요청 메시지 전송 실패"
#define RA_ERRORDETAILS_FAIL_TO_RECV_REPONSE_FROM_CA  "CA로부터 응답 메시지 수신 실패"
#define RA_ERRORDETAILS_ERROR_MESSAGE_FROM_CA         "CA로부터 Error Message 수신"
#define RA_ERRORDETAILS_INVALID_MESSAGE_FROM_CA       "CA로부터 해석할 수 없는 Message 수신"
#define RA_ERRORDETAILS_FAIL_TO_SEND_CONF_TO_CA       "CA로 Confirm Message 전송 실패"

/*## 발급 관련 ##*/
#define RA_STATUSSTRING_CERT_ISSUE_REJECTED_BY_CA     "CA로부터 인증서 발급 받는데 실패"

/*## 폐지 관련 ##*/
#define RA_STATUSSTRING_CERT_REVOKE_REJECTED_BY_CA    "CA에서 인증서 폐지가 거부됨"

#endif // _CMP_STATUS_STRING_RA_HPP_
