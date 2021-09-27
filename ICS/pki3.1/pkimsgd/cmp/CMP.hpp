/**
 * @file    CMP.hpp
 *
 * @desc    CMP 메시지를 처리하는 루틴
 * @author  조현래(hrcho@pentasecurity.com)
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

#include "pkimessage.h" // PKIBody가 전방선언이 불가능한 구조라...

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
    DB::DBObjectSharedPtr pkc;    /**< 발급된 인증서(DB 데이터) */
    DB::DBObjectSharedPtr policy; /**< 인증서 정책(DB 데이터) */
    DB::DBObjectSharedPtr certHolder;
                              /**< 인증서를 발급할 대상에 대한 정보 */
    boost::shared_ptr<PKIReqCertInfo> reqCertInfo;
                              /**< 인증서 발급을 위한 정보들을 저장 */
    boost::shared_ptr<CertResponse> certResponse;
                              /**< CertReqMsg에 대한 response */
    boost::shared_ptr<CertReqMsg> certReqMsg;
                              /**< 해당 CertReqMsg */
    boost::shared_ptr<ASNBuf> encCertSymmKey;
                              /**< POP이 EncCert 방식인 경우에 사용될 비밀키 */

    int reqIndex;             /**< 해당 CertReqMsg가 전체 요청 중 몇번째인지를
                                     나타내는 index값(zero-base) */
    int reqType;              /**< 인증서 요청 메시지의 종류(PKIBody 참조) */

    // RA에서 CA로 인증서 발급 요청을 할 때 사용하는 변수들
    boost::shared_ptr<CertReqMsg> certReqMsgToCA;
                              /**< RA에서 CA로 발급을 요청할 요청 메시지 */
    boost::shared_ptr<PKIReqCertInfo> reqCertInfoToCA;
                              /**< RA에서 CA로 인증서 발급을 위한 정보들을 저장하는 구조체 */
  } ISSUE_CONTEXT;

  typedef struct _REVOKE_CONTEXT
  {
    DB::DBObjectSharedPtr         pkc;    /**< 폐지할 인증서(DB 데이터) */
    DB::DBObjectSharedPtr         certHolder;
                              /**< 인증서를 폐지할 대상에 대한 정보 */

    int reqIndex;             /**< 해당 CertReqMsg가 전체 요청 중 몇번째인지를
                                     나타내는 index값(zero-base) */

    boost::shared_ptr<RevDetails> revDetails;
                              /**< 해당 RevDetails 값 */
    boost::shared_ptr<PKIStatusInfo>
                                  revStatus;
                              /**< RevDetails에 대한 결과를 저장하는 status */
  } REVOKE_CONTEXT;

  CMPSocket _sock;    // entity to authority(this)
  CMPSocket _sockToCA;  // ra(this) to ca

  // 아래의 변수들은 cmp 처리시 복수개의 리퀘스트 메시지가 아니라 하나만 필요한
  // 것들이다. _certHolder는 CONTEXT 별로 필요하지만 현재 CA 구조상 발급시에는
  // 하나라고 가정한다. -> FIXME
  DB::DBObjectSharedPtr           _sender;          /**< 요청자 정보 */
  DB::DBObjectSharedPtr           _senderAuth;      /**< refnum을 삭제할 DB 정보 */
  DB::DBObjectSharedPtr           _certHolder;      /**< 인증서를 발급할 대상에 대한 정보 */
  CnKSharedPtr                    _recipCnK;        /**< 응답 메시지 생성에 사용될
                                                         CA/RA의 인증서 & 비공개키 */
  boost::shared_ptr<PKIMessage>   _reqMessage;      /**< 요청 메시지 */
  boost::shared_ptr<PKIMessage>   _resMessage;      /**< 응답 메시지 */
  boost::shared_ptr<PKIMessage>   _confMessage;     /**< confirm 메시지 */
  boost::shared_ptr<PKISenderAuthInfo>
                                  _confAuthInfo;    /**< confirm 메시지 검증을 위한 정보 */
  boost::shared_ptr<ASNBuf>       _encCertSymmKey;  /**< POP이 EncCert 방식인 경우에 사용될 비밀키 */
  boost::shared_ptr<PKISenderAuthInfo>
                                  _senderAuthInfo;  /**< 요청자 인증을 위한 정보 */
  boost::shared_ptr<PKIBody>      _resBody;         /**< 응답 메시지의 BODY */

  boost::shared_ptr<PKIMessage>   _reqMessageToCA;  /**< 요청 메시지 */
  boost::shared_ptr<PKIMessage>   _resMessageFromCA;/**< 응답 메시지 */
  boost::shared_ptr<PKIContext>   _reqContextToCA;  /**< RA와 CA간의 CMP 요청시 사용될 Context */

  // 복수개의 처리 자료
  std::vector<ISSUE_CONTEXT>      _issueCtx;
  std::vector<REVOKE_CONTEXT>     _revokeCtx;
  std::vector<ISSUE_CONTEXT>      _issueCtxToCA;
  std::vector<REVOKE_CONTEXT>     _revokeCtxToCA;

  bool _certRequest;    /**< CertRequest이면 나중에 confirmMessage가 필요하다. */
  bool _removeRefnum;   /**< 인증코드에 의한 신청이면 발급후 삭제가 필요하다. */
  bool _revocable;
                        /**< confirmMessage처리 실패면 발급된 것 모두 폐지해야 한다. */

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

