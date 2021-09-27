#ifndef _CMP_STATUS_STRING_CA_HPP_
#define _CMP_STATUS_STRING_CA_HPP_

/**
 * @file     CMPStatusStringCA.hpp
 *
 * @desc     CA���� CMP�� ���� �����ϰ� �Ǵ� ���� �޽����� ����
 * @author   ������(hrcho@pentasecurity.com)
 * @since    2001.11.15
 *
 */

/*## ErrorCodes ##*/
enum
{
  ER_CA_FAIL_TO_RECV_MESSAGE  = -10000,   /**< �޽��� ���� ���� */
  ER_CA_INVALID_PROTOCOL,                 /**< �˼� ���� ����� TCP/IP ���� ��� */
  ER_CA_MESSAGE_TOO_LONG,                 /**< �޽��� ���̰� ���ѵ� ���� �ʰ� */
  ER_CA_INVALID_PKIMESSAGE,               /**< �߸��� ����� PKIMessage */
  ER_CA_UNSUPPORTED_PKIMESSAGE_VERSION,   /**< �������� �ʴ� PKIMessage ���� */
  ER_CA_INVALID_HEADER_SENDER,            /**< Header�� sender ���� �߸��Ǿ��� */
  ER_CA_INVALID_HEADER_RECIPIENT,         /**< Header�� recipient ���� �߸��Ǿ��� */
  ER_CA_NULL_HEADER_RECIPIENT,            /**< Header�� recipient ���� NULL�� */
  ER_CA_WRONGAUTHORITY,                   /**< Header�� recipient ���� �� ��������� �ƴ� */
  ER_CA_WRONGAUTHORITY_KID,               /**< Header�� recipKID ���� �� ��������� subjectKeyIdentifier�� ��ġ���� ���� */
  ER_CA_BAD_RECIPIENT_NONCE,              /**< �߸��� recipient nonce �� */
  ER_CA_BAD_TRANSACTION_ID,               /**< �߸��� transaction id �� */

  ER_CA_MISSING_HEADER_SENDERKID,         /**< Header�� senderKID���� ����(secretValue�� ����ϴ� ��쿣 �ݵ�� �����ؾ� ��) */

  ER_CA_UNKNOWN_PROTECTIONALG,            /**< �˼� ���� ����� protection */
  ER_CA_WRONG_MESSAGE_TIME,               /**< PKIMessage�� �ð� ���� ���ѵ� ������ ��� */
  ER_CA_BAD_MESSAGE_CHECK,                /**< PKIMessage�� protection ���� ���� */
  ER_CA_WRONG_INTEGRITY,                  /**< �߸��� ����� protection ���(ir,ccr, genm, rr���� MAC protection�� ����� �� ����) */

  ER_CA_FAIL_TO_FIND_SENDERINFO,          /**< �˼� ���� ��û�� */
  ER_CA_SIGNER_NOT_TRUSTED,               /**< �ŷ��� �� ���� ��û�� */
  ER_CA_REVPASS_NOT_REGISTERED,           /**< RevPassPhrase�� ��ϵǾ� ���� ���� */
  ER_CA_REFNUM_NOT_AVAILABLE,             /**< Reference number�� ���Ⱓ�� �����ų� ���� ��ȿ���� ���� */
  ER_CA_UNSUPPORTED_REQUEST,              /**< �������� ���� Request */

  ER_CA_FAIL_TO_MAKE_PKIMESSAGE,          /**< PKIMessage ���� ���� */
  ER_CA_EMPTY_REQUEST_BODY,               /**< ��û �޽����� Body�� �������. */
  ER_CA_FAIL_TO_FIND_SUBJECTINFO,         /**< DB�κ��� ��û ��� ���� ������ �������µ� ���� */
  ER_CA_FAIL_TO_FIND_SUBJECT_IN_CERTTEMPLATE,
                                          /**< ��û �޽����� certTemplate���� subject���� ã�� �� ���� */
  ER_CA_MULTIPLE_SUBJECTS,                /**< certTemplate�� subject���� ��� �����ؾ� �� */
  ER_CA_REUQESTED_BY_OTHERCA,             /**< CA�� �ٸ� ������� ������ �߱��� ��û�� �� ���� */
  ER_CA_CERTTEMPLATE_SUBJECT_MISMATCH,    /**< ��û �޽����� certTemplate���� subject���� ��û���� subject���� ��ġ���� ���� */
  ER_CA_SENDER_NOT_AUTHORIZED,            /**< ��û�ڿ��� �ٸ� ����� ���� �߱��� ��û�� ������ ���� */
  ER_CA_RA_NOT_AUTHORIZED,                /**< RA�� �ش� ����ڿ� ���� �߱��� ��û�� ������ ���� */
  ER_CA_SUBJECT_NOT_AUTHORIZED,           /**< �߱� ��󿡰� ������ �߱��� �㰡�Ǿ� ���� ���� */
  ER_CA_SUBJECT_VLIMIT_EXPIRED,           /**< �߱� ����� ��ȿ�Ⱓ ���� */
  ER_CA_REQUESTED_USER_DELETED,           /**< ������ ����ڿ� ���� �߱� ��û */
  ER_CA_REQUEST_FOR_THIS_CA_CERT,         /**< �� CA�� ������ �߱� ��û */
  ER_CA_REV_REQUEST_FOR_THIS_CA_CERT,     /**< �� CA�� ������ �߱� ��û */
  ER_CA_CCR_USED_FOR_NON_AUTHORITY,       /**< ccr �޽����� ��ȣ �����ÿ��� ���� */
  ER_CA_FAIL_TO_CONNECT_DB,               /**< DB ���� ���� */

  ER_CA_DB_INTEGRITY_FAIL,                /**< DB ������ ���� ������ �־ ��û�� ó������ ���Ͽ��� */
  ER_CA_DUPLICATE_DN,                     /**< ������ DN���� ���� ���� ����ڰ� ����(RA ��û�� ���) */
  ER_CA_FAIL_TO_GET_RA_ENTITY,            /**< RA ������� �������� �߱��ϱ� ���� �������� DB���� �������µ� ���� */
  ER_CA_DUPLICATE_POLICY_CERT,            /**< �߱� ��û ��å���� ��ȿ�� �������� �̹� ����  */
};

/*## ErrorDetails ##*/
#define CA_ERRORDETAILS_FAIL_TO_RECV_MESSAGE            "�޽��� ���� ����"
#define CA_ERRORDETAILS_INVALID_PROTOCOL                "�˼� ���� ����� TCP/IP ���� ���"
#define CA_ERRORDETAILS_MESSAGE_TOO_LONG                "�޽��� ���̰� ���ѵ� ���� �ʰ�"
#define CA_ERRORDETAILS_INVALID_PKIMESSAGE              "�߸��� ����� PKIMessage"
#define CA_ERRORDETAILS_UNSUPPORTED_PKIMESSAGE_VERSION  "�������� �ʴ� PKIMessage ����"
#define CA_ERRORDETAILS_INVALID_HEADER_SENDER           "Header�� sender ���� �߸��Ǿ���"
#define CA_ERRORDETAILS_INVALID_HEADER_RECIPIENT        "Header�� recipient ���� �߸��Ǿ���"
#define CA_ERRORDETAILS_NULL_HEADER_RECIPIENT           "Header�� recipient ���� NULL��"
#define CA_ERRORDETAILS_WRONGAUTHORITY                  "Header�� recipient ���� �� ���� ����� �ƴ�"
#define CA_ERRORDETAILS_WRONGAUTHORITY_KID              "Header�� recipKID ���� �� ���� ����� subjectKeyIdentifier�� ��ġ���� ����"
#define CA_ERRORDETAILS_BAD_RECIPIENT_NONCE             "�߸��� recipient nonce ��"
#define CA_ERRORDETAILS_BAD_TRANSACTION_ID              "�߸��� transaction id ��"

#define CA_ERRORDETAILS_MISSING_HEADER_SENDERKID        "Header�� senderKID���� ����(secretValue�� ����ϴ� ��쿣 �ݵ�� �����ؾ� ��)"

#define CA_ERRORDETAILS_UNKNOWN_PROTECTIONALG           "�˼� ���� ����� protection"
#define CA_ERRORDETAILS_WRONG_MESSAGE_TIME              "PKIMessage�� �ð� ���� ���ѵ� ������ ���(��û client�� server �ð��� ���ð� �̻� ���̳�)"
#define CA_ERRORDETAILS_BAD_MESSAGE_CHECK               "PKIMessage�� protection ���� ����(offline �߱��� ��� : ������ �߸���, online �߱��� ��� : reference value�� �߸� �Էµ�"
#define CA_ERRORDETAILS_WRONG_INTEGRITY                 "�߸��� ����� protection ���(ir,ccr, genm, rr���� MAC protection�� ����� �� ����)"

#define CA_ERRORDETAILS_UNSUPPORTED_REQUEST             "�������� ���� Request"
#define CA_ERRORDETAILS_FAIL_TO_MAKE_PKIMESSAGE         "PKIMessage ���� ����"
#define CA_ERRORDETAILS_EMPTY_REQUEST_BODY              "��û �޽����� Body�� �������"
#define CA_ERRORDETAILS_FAIL_TO_FIND_SUBJECTINFO        "DB�κ��� ��û ��� ���� ������ �������µ� ����"
#define CA_ERRORDETAILS_FAIL_TO_FIND_SUBJECT_IN_CERTTEMPLATE \
                                                        "��û �޽����� certTemplate���� subject���� ã�� �� ����"
#define CA_ERRORDETAILS_MULTIPLE_SUBJECTS               "certTemplate�� subject���� ��� �����ؾ� ��"
#define CA_ERRORDETAILS_REUQESTED_BY_OTHERCA            "CA�� �ٸ� ������� ������ �߱��� ��û�� �� ����"
#define CA_ERRORDETAILS_CERTTEMPLATE_SUBJECT_MISMATCH   "��û �޽����� certTemplate���� subject���� ��û���� subject���� ��ġ���� ����"
#define CA_ERRORDETAILS_SENDER_NOT_AUTHORIZED           "��û�ڿ��� �ٸ� ����� ���� �߱��� ��û�� ������ ����"
#define CA_ERRORDETAILS_RA_NOT_AUTHORIZED               "RA�� �ش� ����ڿ� ���� �߱��� ��û�� ������ ����"
#define CA_ERRORDETAILS_SUBJECT_NOT_AUTHORIZED          "�߱� ��󿡰� ������ �߱��� �㰡�Ǿ� ���� ����"
#define CA_ERRORDETAILS_SUBJECT_VLIMIT_EXPIRED          "�߱� ����� ��ȿ�Ⱓ ����"
#define CA_ERRORDETAILS_REQUESTED_USER_DELETED          "������ ����ڿ� ���� �߱� ��û"
#define CA_ERRORDETAILS_REQUEST_FOR_THIS_CA_CERT        "�� CA�� ������ �߱� ��û"
#define CA_ERRORDETAILS_REV_REQUEST_FOR_THIS_CA_CERT    "�� CA�� ������ ���� ��û"
#define CA_ERRORDETAILS_CCR_USED_FOR_NON_AUTHORITY      "ccr �޽����� ��ȣ �����ÿ��� ����"
#define CA_ERRORDETAILS_FAIL_TO_CONNECT_DB              "DB ���� ����"
#define CA_ERRORDETAILS_FAIL_TO_FIND_SENDERINFO         "�˼� ���� ��û��(online �߱��� ��� : reference number�� �߸� �Է��Ͽ��� ���ɼ��� ����)"
#define CA_ERRORDETAILS_REVPASS_NOT_REGISTERED          "RevPassPhrase�� ��ϵǾ� ���� ����"
#define CA_ERRORDETAILS_SIGNER_NOT_TRUSTED              "�ŷ��� �� ���� ��û��"
#define CA_ERRORDETAILS_REFNUM_NOT_AVAILABLE            "Reference number�� ���Ⱓ�� �����ų� ���� ��ȿ���� ����"
#define CA_ERRORDETAILS_DB_INTEGRITY_FAIL               "DB ������ ���� ������ �־ ��û�� ó������ ���Ͽ���"
#define CA_ERRORDETAILS_DUPLICATE_DN                    "������ DN���� ���� ���� ����ڰ� ����"
#define CA_ERRORDETAILS_FAIL_TO_GET_RA_ENTITY           "RA ������� �������� �߱��ϱ� ���� �������� DB���� �������µ� ����"
#define CA_ERRORDETAILS_DUPLICATE_POLICY_CERT           "�߱� ��û ��å���� ��ȿ�� �������� �̹� ����"


/*## CA System ���� ##*/
#define CA_STATUSSTRING_DB_INTEGRITY_FAIL     "DB ������ ���� ������ �־ ��û�� ó������ ���Ͽ���"
#define CA_STATUSSTRING_DB_FAIL               "DB�� ������ �־ ��û�� ó������ ���Ͽ���"

/*## �߱� ���� ##*/
#define CA_STATUSSTRING_ISSUE_CERTTMPL_INVALID_ISSUER     "������ ��û �޽����� certTemplate���� issuer���� �߸��Ǿ���"
#define CA_STATUSSTRING_ISSUE_CERTTMPL_INVALID_VERSION    "������ ��û �޽����� certTemplate���� version���� �߸��Ǿ���"
#define CA_STATUSSTRING_ISSUE_CERTTMPL_INVALID_SUBJECT    "������ ��û �޽����� certTemplate���� subject���� �߸��Ǿ���"
#define CA_STATUSSTRING_ISSUE_CERTTMPL_INVALID_SIGNALG    "������ ��û �޽����� certTemplate���� signingAlg���� �߸��Ǿ���"
#define CA_STATUSSTRING_ISSUE_INVALID_CERTREQMSG          "������ ��û �޽����� CertReqMsg ���� �߸��Ǿ���"
#define CA_STATUSSTRING_ISSUE_FAIL_TO_DECRYPT_PRIKEY      "PKIArchiveOptions ���� �����Ű ��ȣȭ ����"
#define CA_STATUSSTRING_ISSUE_FAIL_TO_VERIFY_POP          "�����Ű�� POP(Proof of possesion) ���� ����"
#define CA_STATUSSTRING_ISSUE_FAIL_TO_GEN_CERT            "������ ���� ����"
#define CA_STATUSSTRING_ISSUE_FAIL_TO_INSERT_CERT_TO_DB   "�������� DB�� �߰��ϴµ� �����Ͽ���"
#define CA_STATUSSTRING_ISSUE_FAIL_TO_MAKE_RESPONSE       "���� �޽��� ���� ����"
#define CA_STATUSSTRING_ISSUE_INCORRECT_NUM_OF_CERTREQ    "������ ��û �޽����� ������ �������� ��ġ���� ����"
#define CA_STATUSSTRING_ISSUE_WRONG_PUBLICKEY_LEN         "����Ű ���̰� �������� ��ġ���� ����"
#define CA_STATUSSTRING_ISSUE_WRONG_PUBLICKEY_ALG         "����Ű �˰����� �������� ��ġ���� ����"
#define CA_STATUSSTRING_ISSUE_WRONG_DOMAINPARAM           "����Ű �˰��� ���� ������ �Ķ���� ���� �������� ��ġ���� ����"
#define CA_STATUSSTRING_ISSUE_MISSING_PRIVATEKEY          "�����Ű�� �����ϵ��� �Ǿ� ������ �����Ű�� ���޵Ǿ� ���� �ʾ���"
#define CA_STATUSSTRING_ISSUE_FAIL_TO_CHECKPOLICY         "������ ��û �޽����� ��å�� ��ġ�ϴ��� �����ϴµ� ����"
#define CA_STATUSSTRING_ISSUE_BADCERTID                   "�߸��� CertId ��"
#define CA_STATUSSTRING_ISSUE_BADKEYPOLICYID              "�߸��� Key DBPolicy ID ��"
#define CA_STATUSSTRING_ISSUE_NO_CROSSCA_CERT             "�������� �߱��� ��ȣ ��������� �������� DB�� �� ���� ����"
#define CA_STATUSSTRING_ISSUE_DB_INTEGRITY_FAIL           "DB ������ ���� ������ �־ �߱� ��û�� ó������ ���Ͽ���"
#define CA_STATUSSTRING_ISSUE_FAIL_TO_RESOLVE_ARCHIVEOPTS "pkiArchiveOptions �ؼ� ����"
#define CA_STATUSSTRING_ISSUE_UNSUPPORTED_PKIARCHIVEOPTS  "�������� �ʴ� ����� pkiArhiveOptions"

/*## ���� ���� ##*/
#define CA_STATUSSTRING_REVOKE_NO_SERIALNUMBER            "���� ��û �޽����� ������ �������� �Ϸ� ��ȣ�� ���ԵǾ� ���� ����"
#define CA_STATUSSTRING_REVOKE_CERTREVOKED                "�̹� ������ �� �������� ���� ���� ��û"
#define CA_STATUSSTRING_REVOKE_CERTEXPIRED                "�̹� ���ᰡ �� �������� ���� ���� ��û"
#define CA_STATUSSTRING_REVOKE_BADCERTID                  "�ش� �������� ã�� �� ����"
#define CA_STATUSSTRING_REVOKE_SENDER_NOT_AUTHORIZED      "��û�ڿ��� �ش� �������� ���� ���� ��û�� �� ������ ����"


#endif
