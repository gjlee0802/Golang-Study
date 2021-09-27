/**
 * @file    CMP.hpp
 *
 * @desc    CMP �޽����� ó���ϴ� ��ƾ
 * @author  ������(hrcho@pentasecurity.com)
 * @since   2003.08.06
 */

#ifndef ISSAC_CMP_HPP_
#define ISSAC_CMP_HPP_

// forward declarations for cis
typedef struct _ErrorMsgContent ErrorMsgContent;
typedef struct _PKIMessage PKIMessage;
typedef struct _PKIReqCertInfo PKIReqCertInfo;
typedef struct _CertResponse CertResponse;
typedef struct _CertReqMsg CertReqMsg;
typedef struct _RevDetails RevDetails;
typedef struct _PKIStatusInfo PKIStatusInfo;
typedef struct _PKISenderAuthInfo PKISenderAuthInfo;
typedef struct _PKIContext PKIContext;

#include "pkimessage.h" // PKIBody�� ���漱���� �Ұ����� ������...

#include "CnK_define.hpp"
#include "CMPSocket.hpp"
#include "DBSubject.hpp"

namespace Issac
{

class CMP
{
public:
  CMP() {}
  virtual ~CMP();

  void process(CMPSocket sockConn);

  // to override CDP URI to set CDP in PKIENTITYPKC table
  // related to partitioned crl
  static bool isPCRL();
  static std::string getPCRL_CdpUriFormat();
  static std::string getPCRL_CdpUri(int certCount);
  static int getPCRL_UnitCerts();
  static int getPCRL_CurrentCertsCount();

protected:
  typedef struct _ISSUE_CONTEXT
  {
    DB::DBObjectSharedPtr pkc;    /**< �߱޵� ������(DB ������) */
    DB::DBObjectSharedPtr policy; /**< ������ ��å(DB ������) */
    DB::DBObjectSharedPtr certHolder;
                              /**< �������� �߱��� ��� ���� ���� */
    boost::shared_ptr<PKIReqCertInfo> reqCertInfo;
                              /**< ������ �߱��� ���� �������� ���� */
    boost::shared_ptr<CertResponse> certResponse;
                              /**< CertReqMsg�� ���� response */
    boost::shared_ptr<CertReqMsg> certReqMsg;
                              /**< �ش� CertReqMsg */
    boost::shared_ptr<ASNBuf> encCertSymmKey;
                              /**< POP�� EncCert ����� ��쿡 ���� ���Ű */

    int reqIndex;             /**< �ش� CertReqMsg�� ��ü ��û �� ���°������
                                     ��Ÿ���� index��(zero-base) */
    int reqType;              /**< ������ ��û �޽����� ����(PKIBody ����) */

    // RA���� CA�� ������ �߱� ��û�� �� �� ����ϴ� ������
    boost::shared_ptr<CertReqMsg> certReqMsgToCA;
                              /**< RA���� CA�� �߱��� ��û�� ��û �޽��� */
    boost::shared_ptr<PKIReqCertInfo> reqCertInfoToCA;
                              /**< RA���� CA�� ������ �߱��� ���� �������� �����ϴ� ����ü */
  } ISSUE_CONTEXT;

  typedef struct _REVOKE_CONTEXT
  {
    DB::DBObjectSharedPtr         pkc;    /**< ������ ������(DB ������) */
    DB::DBObjectSharedPtr         certHolder;
                              /**< �������� ������ ��� ���� ���� */

    int reqIndex;             /**< �ش� CertReqMsg�� ��ü ��û �� ���°������
                                     ��Ÿ���� index��(zero-base) */

    boost::shared_ptr<RevDetails> revDetails;
                              /**< �ش� RevDetails �� */
    boost::shared_ptr<PKIStatusInfo>
                                  revStatus;
                              /**< RevDetails�� ���� ����� �����ϴ� status */
  } REVOKE_CONTEXT;

  CMPSocket _sock;    // entity to authority(this)
  CMPSocket _sockToCA;  // ra(this) to ca

  // �Ʒ��� �������� cmp ó���� �������� ������Ʈ �޽����� �ƴ϶� �ϳ��� �ʿ���
  // �͵��̴�. _certHolder�� CONTEXT ���� �ʿ������� ���� CA ������ �߱޽ÿ���
  // �ϳ���� �����Ѵ�. -> FIXME
  DB::DBObjectSharedPtr           _sender;          /**< ��û�� ���� */
  DB::DBObjectSharedPtr           _senderAuth;      /**< refnum�� ������ DB ���� */
  DB::DBObjectSharedPtr           _certHolder;      /**< �������� �߱��� ��� ���� ���� */
  CnKSharedPtr                    _recipCnK;        /**< ���� �޽��� ������ ����
                                                         CA/RA�� ������ & �����Ű */
  boost::shared_ptr<PKIMessage>   _reqMessage;      /**< ��û �޽��� */
  boost::shared_ptr<PKIMessage>   _resMessage;      /**< ���� �޽��� */
  boost::shared_ptr<PKIMessage>   _confMessage;     /**< confirm �޽��� */
  boost::shared_ptr<PKISenderAuthInfo>
                                  _confAuthInfo;    /**< confirm �޽��� ������ ���� ���� */
  boost::shared_ptr<ASNBuf>       _encCertSymmKey;  /**< POP�� EncCert ����� ��쿡 ���� ���Ű */
  boost::shared_ptr<PKISenderAuthInfo>
                                  _senderAuthInfo;  /**< ��û�� ������ ���� ���� */
  boost::shared_ptr<PKIBody>      _resBody;         /**< ���� �޽����� BODY */

  boost::shared_ptr<PKIMessage>   _reqMessageToCA;  /**< ��û �޽��� */
  boost::shared_ptr<PKIMessage>   _resMessageFromCA;/**< ���� �޽��� */
  boost::shared_ptr<PKIContext>   _reqContextToCA;  /**< RA�� CA���� CMP ��û�� ���� Context */

  // �������� ó�� �ڷ�
  std::vector<ISSUE_CONTEXT>      _issueCtx;
  std::vector<REVOKE_CONTEXT>     _revokeCtx;
  std::vector<ISSUE_CONTEXT>      _issueCtxToCA;
  std::vector<REVOKE_CONTEXT>     _revokeCtxToCA;

  bool _certRequest;    /**< CertRequest�̸� ���߿� confirmMessage�� �ʿ��ϴ�. */
  bool _removeRefnum;   /**< �����ڵ忡 ���� ��û�̸� �߱��� ������ �ʿ��ϴ�. */
  bool _revocable;
                        /**< confirmMessageó�� ���и� �߱޵� �� ��� �����ؾ� �Ѵ�. */

  void verifyMessage(PKIMessage *pkiMessage, PKISenderAuthInfo *senderAuthInfo);
  static void verifyProtection(PKIMessage *pkiMessage, PKISenderAuthInfo *senderAuthInfo);
  static void checkSenderPrivilege(Issac::DB::DBSubject *sender, Issac::DB::DBSubject *certHolder);

  void sendErrorMessage(ErrorMsgContent *content);

  // start main process
  // try
    void recvReqMessage();
    void getSender(); // from CMP_getSender.cpp
    void verifyReqMessage();
    void dispatchAndProcessRequest();
    void makeResMessage();
    void sendResMessage();
    // if (_certProcess)
      void recvConfMessage();
      void verifyConfMessage();
      void dispatchConfMessage();
      // if RA
        void sendConfMessageToCA();
    // if (_removeRefNum)
      void removeRefnum();
  // catch
    // if (_revocable)
      void revokeUnconfirmedCerts();
  // end main process


  // in main functions ....
  // in dispatchAndProcessRequest();
    // switch(_reqMessage.get()->body->select)
      void processCertRequest();
      void processRevokeRequest();
      void processGeneralMsg();

    //* in processCertRequest
      void getCertHolder();
      void checkSenderCanIssue();
        // void checkSenderPrivilege(); ->helper function
      void issueCerts();

      // in issueCerts()
          // verify validity
          void resolveCertReqMsg(ISSUE_CONTEXT &ctx);
            void checkCertTemplate(ISSUE_CONTEXT &ctx);
            void verifyPOP(ISSUE_CONTEXT &ctx);
            void checkControls(ISSUE_CONTEXT &ctx);
          void getIssueInfo(ISSUE_CONTEXT &ctx);
            static void getPreviousKeyId(PKIReqCertInfo *reqCertInfo,
                                         Certificate *prevCert);
          void checkPolicy(ISSUE_CONTEXT &ctx);
        // if CA
          void makeCerts();
            void makeOneCert(ISSUE_CONTEXT &ctx);
            void setEncryptedPrivateKey();
        // if RA
          void recvCertsFromCA();
            void makeCertReq(ISSUE_CONTEXT &ctx);
            void requestCertsToCA();

        void makeCertResponse();
          void makeOneCertResponse(ISSUE_CONTEXT &ctx);

    //* in processRevokeRequest()
      void initRevokeContext();
      void resolveRevDetails();
      void checkSenderCanRevoke();
      // if CA
        void revokeCerts();
          void makeRevMassageToCA();
          void sendAndRecvMessageWithCA();
          void resolveRevResMessageFromCA();
      // else
        void requestRevokeToCA();
      void makeRevokeResContest();

    //* in processGeneralMsg()
      InfoTypeAndValue *getKeyPolicy(InfoTypeAndValue *infoReq);

  // helper function - log
  static std::string getLogReqInfo(
          boost::shared_ptr<Issac::DB::DBObjectBase> requester,
          std::string peerName);
  static std::string getLogHolderInfo(
          boost::shared_ptr<Issac::DB::DBObjectBase> certHolder);
};

}

#endif // ISSAC_CMP_HPP_

