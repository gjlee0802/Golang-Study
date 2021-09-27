#ifndef _CMP_STATUS_STRING_CA_HPP_
#define _CMP_STATUS_STRING_CA_HPP_

/**
 * @file     CMPStatusStringCA.hpp
 *
 * @desc     CA에서 CMP를 통해 전달하게 되는 에러 메시지들 정의
 * @author   조현래(hrcho@pentasecurity.com)
 * @since    2001.11.15
 *
 */

/*## ErrorCodes ##*/
enum
{
  ER_CA_FAIL_TO_RECV_MESSAGE  = -10000,   /**< 메시지 수신 실패 */
  ER_CA_INVALID_PROTOCOL,                 /**< 알수 없는 방식의 TCP/IP 전송 방식 */
  ER_CA_MESSAGE_TOO_LONG,                 /**< 메시지 길이가 제한된 값을 초과 */
  ER_CA_INVALID_PKIMESSAGE,               /**< 잘못된 방식의 PKIMessage */
  ER_CA_UNSUPPORTED_PKIMESSAGE_VERSION,   /**< 지원되지 않는 PKIMessage 버전 */
  ER_CA_INVALID_HEADER_SENDER,            /**< Header의 sender 값이 잘못되었음 */
  ER_CA_INVALID_HEADER_RECIPIENT,         /**< Header의 recipient 값이 잘못되었음 */
  ER_CA_NULL_HEADER_RECIPIENT,            /**< Header의 recipient 값이 NULL임 */
  ER_CA_WRONGAUTHORITY,                   /**< Header의 recipient 값이 현 인증기관이 아님 */
  ER_CA_WRONGAUTHORITY_KID,               /**< Header의 recipKID 값이 현 인증기관의 subjectKeyIdentifier와 일치하지 않음 */
  ER_CA_BAD_RECIPIENT_NONCE,              /**< 잘못된 recipient nonce 값 */
  ER_CA_BAD_TRANSACTION_ID,               /**< 잘못된 transaction id 값 */

  ER_CA_MISSING_HEADER_SENDERKID,         /**< Header의 senderKID값이 없음(secretValue를 사용하는 경우엔 반드시 존재해야 함) */

  ER_CA_UNKNOWN_PROTECTIONALG,            /**< 알수 없는 방식의 protection */
  ER_CA_WRONG_MESSAGE_TIME,               /**< PKIMessage의 시간 값이 제한된 범위를 벗어남 */
  ER_CA_BAD_MESSAGE_CHECK,                /**< PKIMessage의 protection 검증 실패 */
  ER_CA_WRONG_INTEGRITY,                  /**< 잘못된 방식의 protection 방식(ir,ccr, genm, rr만이 MAC protection을 사용할 수 있음) */

  ER_CA_FAIL_TO_FIND_SENDERINFO,          /**< 알수 없는 요청자 */
  ER_CA_SIGNER_NOT_TRUSTED,               /**< 신뢰할 수 없는 요청자 */
  ER_CA_REVPASS_NOT_REGISTERED,           /**< RevPassPhrase가 등록되어 있지 않음 */
  ER_CA_REFNUM_NOT_AVAILABLE,             /**< Reference number의 사용기간이 지났거나 아직 유효하지 않음 */
  ER_CA_UNSUPPORTED_REQUEST,              /**< 지원되지 않은 Request */

  ER_CA_FAIL_TO_MAKE_PKIMESSAGE,          /**< PKIMessage 생성 실패 */
  ER_CA_EMPTY_REQUEST_BODY,               /**< 요청 메시지의 Body가 비어있음. */
  ER_CA_FAIL_TO_FIND_SUBJECTINFO,         /**< DB로부터 요청 대상에 대한 정보를 가져오는데 실패 */
  ER_CA_FAIL_TO_FIND_SUBJECT_IN_CERTTEMPLATE,
                                          /**< 요청 메시지의 certTemplate에서 subject값을 찾을 수 없음 */
  ER_CA_MULTIPLE_SUBJECTS,                /**< certTemplate의 subject값은 모두 동일해야 함 */
  ER_CA_REUQESTED_BY_OTHERCA,             /**< CA는 다른 사용자의 인증서 발급을 요청할 수 없음 */
  ER_CA_CERTTEMPLATE_SUBJECT_MISMATCH,    /**< 요청 메시지의 certTemplate내의 subject값이 요청자의 subject값과 일치하지 않음 */
  ER_CA_SENDER_NOT_AUTHORIZED,            /**< 신청자에게 다른 사람에 대한 발급을 요청할 권한이 없음 */
  ER_CA_RA_NOT_AUTHORIZED,                /**< RA가 해당 사용자에 대한 발급을 요청할 권한이 없음 */
  ER_CA_SUBJECT_NOT_AUTHORIZED,           /**< 발급 대상에게 인증서 발급이 허가되어 있지 않음 */
  ER_CA_SUBJECT_VLIMIT_EXPIRED,           /**< 발급 대상의 유효기간 만료 */
  ER_CA_REQUESTED_USER_DELETED,           /**< 삭제된 사용자에 대한 발급 요청 */
  ER_CA_REQUEST_FOR_THIS_CA_CERT,         /**< 현 CA의 인증서 발급 요청 */
  ER_CA_REV_REQUEST_FOR_THIS_CA_CERT,     /**< 현 CA의 인증서 발급 요청 */
  ER_CA_CCR_USED_FOR_NON_AUTHORITY,       /**< ccr 메시지는 상호 인증시에만 사용됨 */
  ER_CA_FAIL_TO_CONNECT_DB,               /**< DB 연결 실패 */

  ER_CA_DB_INTEGRITY_FAIL,                /**< DB 데이터 값에 문제가 있어서 요청을 처리하지 못하였음 */
  ER_CA_DUPLICATE_DN,                     /**< 동일한 DN값을 갖는 기존 사용자가 존재(RA 요청인 경우) */
  ER_CA_FAIL_TO_GET_RA_ENTITY,            /**< RA 사용자의 인증서를 발급하기 위한 정보들을 DB에서 가져오는데 실패 */
  ER_CA_DUPLICATE_POLICY_CERT,            /**< 발급 요청 정책으로 유효한 인증서가 이미 존재  */
};

/*## ErrorDetails ##*/
#define CA_ERRORDETAILS_FAIL_TO_RECV_MESSAGE            "메시지 수신 실패"
#define CA_ERRORDETAILS_INVALID_PROTOCOL                "알수 없는 방식의 TCP/IP 전송 방식"
#define CA_ERRORDETAILS_MESSAGE_TOO_LONG                "메시지 길이가 제한된 값을 초과"
#define CA_ERRORDETAILS_INVALID_PKIMESSAGE              "잘못된 방식의 PKIMessage"
#define CA_ERRORDETAILS_UNSUPPORTED_PKIMESSAGE_VERSION  "지원되지 않는 PKIMessage 버전"
#define CA_ERRORDETAILS_INVALID_HEADER_SENDER           "Header의 sender 값이 잘못되었음"
#define CA_ERRORDETAILS_INVALID_HEADER_RECIPIENT        "Header의 recipient 값이 잘못되었음"
#define CA_ERRORDETAILS_NULL_HEADER_RECIPIENT           "Header의 recipient 값이 NULL임"
#define CA_ERRORDETAILS_WRONGAUTHORITY                  "Header의 recipient 값이 현 인증 기관이 아님"
#define CA_ERRORDETAILS_WRONGAUTHORITY_KID              "Header의 recipKID 값이 현 인증 기관의 subjectKeyIdentifier와 일치하지 않음"
#define CA_ERRORDETAILS_BAD_RECIPIENT_NONCE             "잘못된 recipient nonce 값"
#define CA_ERRORDETAILS_BAD_TRANSACTION_ID              "잘못된 transaction id 값"

#define CA_ERRORDETAILS_MISSING_HEADER_SENDERKID        "Header의 senderKID값이 없음(secretValue를 사용하는 경우엔 반드시 존재해야 함)"

#define CA_ERRORDETAILS_UNKNOWN_PROTECTIONALG           "알수 없는 방식의 protection"
#define CA_ERRORDETAILS_WRONG_MESSAGE_TIME              "PKIMessage의 시간 값이 제한된 범위를 벗어남(요청 client와 server 시간이 수시간 이상 차이남)"
#define CA_ERRORDETAILS_BAD_MESSAGE_CHECK               "PKIMessage의 protection 검증 실패(offline 발급의 경우 : 서명이 잘못됨, online 발급의 경우 : reference value가 잘못 입력됨"
#define CA_ERRORDETAILS_WRONG_INTEGRITY                 "잘못된 방식의 protection 방식(ir,ccr, genm, rr만이 MAC protection을 사용할 수 있음)"

#define CA_ERRORDETAILS_UNSUPPORTED_REQUEST             "지원되지 않은 Request"
#define CA_ERRORDETAILS_FAIL_TO_MAKE_PKIMESSAGE         "PKIMessage 생성 실패"
#define CA_ERRORDETAILS_EMPTY_REQUEST_BODY              "요청 메시지의 Body가 비어있음"
#define CA_ERRORDETAILS_FAIL_TO_FIND_SUBJECTINFO        "DB로부터 요청 대상에 대한 정보를 가져오는데 실패"
#define CA_ERRORDETAILS_FAIL_TO_FIND_SUBJECT_IN_CERTTEMPLATE \
                                                        "요청 메시지의 certTemplate에서 subject값을 찾을 수 없음"
#define CA_ERRORDETAILS_MULTIPLE_SUBJECTS               "certTemplate의 subject값은 모두 동일해야 함"
#define CA_ERRORDETAILS_REUQESTED_BY_OTHERCA            "CA는 다른 사용자의 인증서 발급을 요청할 수 없음"
#define CA_ERRORDETAILS_CERTTEMPLATE_SUBJECT_MISMATCH   "요청 메시지의 certTemplate내의 subject값이 요청자의 subject값과 일치하지 않음"
#define CA_ERRORDETAILS_SENDER_NOT_AUTHORIZED           "신청자에게 다른 사람에 대한 발급을 요청할 권한이 없음"
#define CA_ERRORDETAILS_RA_NOT_AUTHORIZED               "RA가 해당 사용자에 대한 발급을 요청할 권한이 없음"
#define CA_ERRORDETAILS_SUBJECT_NOT_AUTHORIZED          "발급 대상에게 인증서 발급이 허가되어 있지 않음"
#define CA_ERRORDETAILS_SUBJECT_VLIMIT_EXPIRED          "발급 대상의 유효기간 만료"
#define CA_ERRORDETAILS_REQUESTED_USER_DELETED          "삭제된 사용자에 대한 발급 요청"
#define CA_ERRORDETAILS_REQUEST_FOR_THIS_CA_CERT        "현 CA의 인증서 발급 요청"
#define CA_ERRORDETAILS_REV_REQUEST_FOR_THIS_CA_CERT    "현 CA의 인증서 폐지 요청"
#define CA_ERRORDETAILS_CCR_USED_FOR_NON_AUTHORITY      "ccr 메시지는 상호 인증시에만 사용됨"
#define CA_ERRORDETAILS_FAIL_TO_CONNECT_DB              "DB 연결 실패"
#define CA_ERRORDETAILS_FAIL_TO_FIND_SENDERINFO         "알수 없는 요청자(online 발급의 경우 : reference number를 잘못 입력하였을 가능성이 있음)"
#define CA_ERRORDETAILS_REVPASS_NOT_REGISTERED          "RevPassPhrase가 등록되어 있지 않음"
#define CA_ERRORDETAILS_SIGNER_NOT_TRUSTED              "신뢰할 수 없는 요청자"
#define CA_ERRORDETAILS_REFNUM_NOT_AVAILABLE            "Reference number의 사용기간이 지났거나 아직 유효하지 않음"
#define CA_ERRORDETAILS_DB_INTEGRITY_FAIL               "DB 데이터 값에 문제가 있어서 요청을 처리하지 못하였음"
#define CA_ERRORDETAILS_DUPLICATE_DN                    "동일한 DN값을 갖는 기존 사용자가 존재"
#define CA_ERRORDETAILS_FAIL_TO_GET_RA_ENTITY           "RA 사용자의 인증서를 발급하기 위한 정보들을 DB에서 가져오는데 실패"
#define CA_ERRORDETAILS_DUPLICATE_POLICY_CERT           "발급 요청 정책으로 유효한 인증서가 이미 존재"


/*## CA System 관련 ##*/
#define CA_STATUSSTRING_DB_INTEGRITY_FAIL     "DB 데이터 값에 문제가 있어서 요청을 처리하지 못하였음"
#define CA_STATUSSTRING_DB_FAIL               "DB에 문제가 있어서 요청을 처리하지 못하였음"

/*## 발급 관련 ##*/
#define CA_STATUSSTRING_ISSUE_CERTTMPL_INVALID_ISSUER     "인증서 요청 메시지의 certTemplate내의 issuer값이 잘못되었음"
#define CA_STATUSSTRING_ISSUE_CERTTMPL_INVALID_VERSION    "인증서 요청 메시지의 certTemplate내의 version값이 잘못되었음"
#define CA_STATUSSTRING_ISSUE_CERTTMPL_INVALID_SUBJECT    "인증서 요청 메시지의 certTemplate내의 subject값이 잘못되었음"
#define CA_STATUSSTRING_ISSUE_CERTTMPL_INVALID_SIGNALG    "인증서 요청 메시지의 certTemplate내의 signingAlg값이 잘못되었음"
#define CA_STATUSSTRING_ISSUE_INVALID_CERTREQMSG          "인증서 요청 메시지의 CertReqMsg 값이 잘못되었음"
#define CA_STATUSSTRING_ISSUE_FAIL_TO_DECRYPT_PRIKEY      "PKIArchiveOptions 내의 비공개키 복호화 실패"
#define CA_STATUSSTRING_ISSUE_FAIL_TO_VERIFY_POP          "비공개키의 POP(Proof of possesion) 검증 실패"
#define CA_STATUSSTRING_ISSUE_FAIL_TO_GEN_CERT            "인증서 생성 실패"
#define CA_STATUSSTRING_ISSUE_FAIL_TO_INSERT_CERT_TO_DB   "인증서를 DB에 추가하는데 실패하였음"
#define CA_STATUSSTRING_ISSUE_FAIL_TO_MAKE_RESPONSE       "응답 메시지 생성 실패"
#define CA_STATUSSTRING_ISSUE_INCORRECT_NUM_OF_CERTREQ    "인증서 요청 메시지의 개수가 설정값과 일치하지 않음"
#define CA_STATUSSTRING_ISSUE_WRONG_PUBLICKEY_LEN         "공개키 길이가 설정값과 일치하지 않음"
#define CA_STATUSSTRING_ISSUE_WRONG_PUBLICKEY_ALG         "공개키 알고리즘이 설정값과 일치하지 않음"
#define CA_STATUSSTRING_ISSUE_WRONG_DOMAINPARAM           "공개키 알고리즘 내의 도메인 파라메터 값이 설정값과 일치하지 않음"
#define CA_STATUSSTRING_ISSUE_MISSING_PRIVATEKEY          "비공개키를 저장하도록 되어 있으나 비공개키가 전달되어 오지 않았음"
#define CA_STATUSSTRING_ISSUE_FAIL_TO_CHECKPOLICY         "인증서 요청 메시지가 정책에 일치하는지 검증하는데 실패"
#define CA_STATUSSTRING_ISSUE_BADCERTID                   "잘못된 CertId 값"
#define CA_STATUSSTRING_ISSUE_BADKEYPOLICYID              "잘못된 Key DBPolicy ID 값"
#define CA_STATUSSTRING_ISSUE_NO_CROSSCA_CERT             "인증서를 발급할 상호 인증기관의 인증서가 DB에 들어가 있지 않음"
#define CA_STATUSSTRING_ISSUE_DB_INTEGRITY_FAIL           "DB 데이터 값에 문제가 있어서 발급 요청을 처리하지 못하였음"
#define CA_STATUSSTRING_ISSUE_FAIL_TO_RESOLVE_ARCHIVEOPTS "pkiArchiveOptions 해석 실패"
#define CA_STATUSSTRING_ISSUE_UNSUPPORTED_PKIARCHIVEOPTS  "지원되지 않는 방식의 pkiArhiveOptions"

/*## 폐지 관련 ##*/
#define CA_STATUSSTRING_REVOKE_NO_SERIALNUMBER            "폐지 요청 메시지에 폐지할 인증서의 일련 번호가 포함되어 있지 않음"
#define CA_STATUSSTRING_REVOKE_CERTREVOKED                "이미 폐지가 된 인증서에 대한 폐지 요청"
#define CA_STATUSSTRING_REVOKE_CERTEXPIRED                "이미 만료가 된 인증서에 대한 폐지 요청"
#define CA_STATUSSTRING_REVOKE_BADCERTID                  "해당 인증서를 찾을 수 없음"
#define CA_STATUSSTRING_REVOKE_SENDER_NOT_AUTHORIZED      "요청자에게 해당 인증서에 대해 폐지 요청을 할 권한이 없음"


#endif
