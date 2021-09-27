#ifndef _CMP_STATUS_STRING_RA_HPP_
#define _CMP_STATUS_STRING_RA_HPP_

/**
 * @file     CMPStatusStringRA.hpp
 *
 * @desc     RA���� CMP�� ���� �����ϰ� �Ǵ� ���� �޽����� ����
 * @author   ������(hrcho@pentasecurity.com)
 * @since    2001.11.15
 *
 */

/*## ErrorCodes ##*/
enum
{
  ER_RA_FAIL_TO_MAKE_REQUEST_MESSAGE = -20000,
  ER_RA_CERTTMPL_INVALID_VERSION,   /**< ������ ��û �޽����� certTemplate���� version���� �߸��Ǿ��� */
  ER_RA_CERTTMPL_INVALID_ISSUER,    /**< ������ ��û �޽����� certTemplate���� issuer���� �߸��Ǿ��� */
  ER_RA_CERTTMPL_INVALID_SUBJECT,   /**< ������ ��û �޽����� certTemplate���� subject���� �߸��Ǿ��� */
  ER_RA_CERTTMPL_INVALID_SIGNALG,   /**< ������ ��û �޽����� certTemplate���� signingAlg���� �߸��Ǿ��� */
  ER_RA_FAIL_TO_VERIFY_POP,         /**< �����Ű�� POP(Proof of possesion) ���� ���� */
  ER_RA_INVALID_CERTREQMSG,         /**< ������ ��û �޽����� CertReqMsg ���� �߸��Ǿ��� */
  ER_RA_BAD_KEYPOLICY_ID,           /**< �߸��� Key policy ID */
  ER_RA_BAD_CERTID,                 /**< �߸��� CertId �� */
  ER_RA_INCORRECT_NUM_OF_CERTREQ,   /**< �߱��� ��û�ϴ� �������� ������ ����ڿ��� �����Ǿ� �ִ� ������ ��ġ���� ���� */
  ER_RA_WRONG_PUBLICKEY_ALG,        /**< ����Ű �˰����� �������� ��ġ���� ���� */
  ER_RA_WRONG_PUBLICKEY_LEN,        /**< ����Ű ���̰� �������� ��ġ���� ���� */
  ER_RA_WRONG_DOMAINPARAM,          /**< ����Ű �˰��� ���� ������ �Ķ���� ���� �������� ��ġ���� ���� */
  ER_RA_FAIL_TO_CHECK_POLICY,       /**< ������ ��û �޽����� ����� ��å�� ��ġ���� ���� */
  ER_RA_FAIL_TO_CONNECT_CA,         /**< CA�� ���� ���� */
  ER_RA_FAIL_TO_SEND_REQUEST_TO_CA, /**< CA���� ��û �޽��� ���� ���� */
  ER_RA_FAIL_TO_RECV_REPONSE_FROM_CA, /**< CA�κ��� ���� �޽��� ���� ���� */
  ER_RA_ERROR_MESSAGE_FROM_CA,      /**< CA�κ��� ���� �޽��� ���� */
  ER_RA_INVALID_MESSAGE_FROM_CA,    /**< CA�κ��� �߸��� �޽��� ���� */
  ER_RA_CERT_ISSUE_REJECTED_BY_CA,  /**< CA�κ��� ������ �߱� �޴µ� ���� */
  ER_RA_FAIL_TO_SEND_CONF_TO_CA,    /**< CA�� CONFIRM �޽��� ���� ���� */
};

/*## ErrorDetails ##*/
#define RA_ERRORDETAILS_CERTTMPL_INVALID_VERSION     "������ ��û �޽����� certTemplate���� version���� �߸��Ǿ���"
#define RA_ERRORDETAILS_CERTTMPL_INVALID_ISSUER      "������ ��û �޽����� certTemplate���� issuer���� �߸��Ǿ���"
#define RA_ERRORDETAILS_CERTTMPL_INVALID_SUBJECT     "������ ��û �޽����� certTemplate���� subject���� �߸��Ǿ���"
#define RA_ERRORDETAILS_CERTTMPL_INVALID_SIGNALG     "������ ��û �޽����� certTemplate���� signingAlg���� �߸��Ǿ���"
#define RA_ERRORDETAILS_FAIL_TO_VERIFY_POP            "�����Ű�� POP(Proof of possesion) ���� ����"
#define RA_ERRORDETAILS_INVALID_CERTREQMSG            "������ ��û �޽����� CertReqMsg ���� �߸��Ǿ���"
#define RA_ERRORDETAILS_BAD_KEYPOLICY_ID              "�߸��� Key policy ID"
#define RA_ERRORDETAILS_BAD_CERTID                    "�߸��� CertId ��"
#define RA_ERRORDETAILS_INCORRECT_NUM_OF_CERTREQ      "�߱��� ��û�ϴ� �������� ������ ����ڿ��� �����Ǿ� �ִ� ������ ��ġ���� ����"
#define RA_ERRORDETAILS_WRONG_PUBLICKEY_ALG           "����Ű �˰����� �������� ��ġ���� ����"
#define RA_ERRORDETAILS_WRONG_PUBLICKEY_LEN           "����Ű ���̰� �������� ��ġ���� ����"
#define RA_ERRORDETAILS_WRONG_DOMAINPARAM             "����Ű �˰��� ���� ������ �Ķ���� ���� �������� ��ġ���� ����"
#define RA_ERRORDETAILS_FAIL_TO_CHECK_POLICY          "������ ��û �޽����� ����� ��å�� ��ġ���� ����"
#define RA_ERRORDETAILS_FAIL_TO_MAKE_REQUEST_MESSAGE  "CA���� ��û PKIMessage ���� ����"
#define RA_ERRORDETAILS_FAIL_TO_CONNECT_CA            "CA ���� ����"
#define RA_ERRORDETAILS_FAIL_TO_SEND_REQUEST_TO_CA    "CA���� ��û �޽��� ���� ����"
#define RA_ERRORDETAILS_FAIL_TO_RECV_REPONSE_FROM_CA  "CA�κ��� ���� �޽��� ���� ����"
#define RA_ERRORDETAILS_ERROR_MESSAGE_FROM_CA         "CA�κ��� Error Message ����"
#define RA_ERRORDETAILS_INVALID_MESSAGE_FROM_CA       "CA�κ��� �ؼ��� �� ���� Message ����"
#define RA_ERRORDETAILS_FAIL_TO_SEND_CONF_TO_CA       "CA�� Confirm Message ���� ����"

/*## �߱� ���� ##*/
#define RA_STATUSSTRING_CERT_ISSUE_REJECTED_BY_CA     "CA�κ��� ������ �߱� �޴µ� ����"

/*## ���� ���� ##*/
#define RA_STATUSSTRING_CERT_REVOKE_REJECTED_BY_CA    "CA���� ������ ������ �źε�"

#endif // _CMP_STATUS_STRING_RA_HPP_
