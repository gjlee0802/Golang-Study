// CMP.cpp: implementation of the CMP class.
//
////////////////////////////////////////////////////////////////////////////////

// standard headers
#include <boost/scoped_ptr.hpp>
#include <cassert>

// cis headers
#include "x509pkc.h"
#include "pkimessage.h"

// pki headers
#include "Trace.h"
#include "DBSubject.hpp"
#include "DBPKC.hpp"
#include "DBAuthority.hpp"
#include "CMPSocket.hpp"
#include "CMPException.hpp"
#include "Log.hpp"
#include "CALoginProfile.hpp"
#include "CnK_define.hpp"
#include "PKILogTableDefine.hpp"

#include "CMP.hpp"

using namespace Issac;
using namespace Issac::DB;
using namespace std;

namespace Issac
{

#define TRACEFILE "/tmp/cmp.log"

//  class CMP
//
//////////////////////////////////////////////////////

///// start main function

CMP::~CMP()
{
}

void CMP::process(CMPSocket sockConn)
{
  // initialization codes here...
  _sock = sockConn;
  _issueCtx.clear();
  _revokeCtx.clear();
  _issueCtxToCA.clear();
  _revokeCtxToCA.clear();
  _revocable = _certRequest = _removeRefnum = false;

  try
  {
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    recvReqMessage();
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    getSender(); // from CMP_getSender.cpp
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    verifyReqMessage();
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    dispatchAndProcessRequest();
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    makeResMessage();
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    sendResMessage();
    if (_certRequest)
    {
      recvConfMessage();
      verifyConfMessage();
      dispatchConfMessage();
    }
    if (_removeRefnum)
      removeRefnum();
  }
  catch (CMPException &e)
  {
    try
    {
      if (e.getErrorMsgContent())
      {
        sendErrorMessage(e.getErrorMsgContent());
      }
    }
    catch (...)
    {
    }

    // Log ���
    LogItemSharedPtr logItem = AuthorityLoginProfile::get()->getLog()->createLogItem();
    logItem->setLogItem(e.getCode(), e.getOpts());
    try
    {
      _sock.getPeerName();
      logItem->setRequester(getLogReqInfo(_sender, _sock.getPeerName()));
      logItem->setCertHolder(getLogHolderInfo(_certHolder));
    }
    catch (...)
    {
    }
    logItem->write();

    if (_revocable)
    {
      try
      {
        revokeUnconfirmedCerts();
      }
      catch (...)
      {
      }
    }
  }
  catch (LogException &e)
  {
    LogItemSharedPtr logItem = AuthorityLoginProfile::get()->getLog()->createLogItem();
    logItem->setLogItem(e.getCode(), e.getOpts());
    try
    {
      logItem->setRequester(getLogReqInfo(_sender, _sock.getPeerName()));
      logItem->setCertHolder(getLogHolderInfo(_certHolder));
    }
    catch (...)
    {
    }
    logItem->write();
  }
  catch (exception &e)
  {
  }
  catch (...)
  {
  }
}

void CMP::sendErrorMessage(ErrorMsgContent *content)
{
  int ret;
  CnKSharedPtr recipCnK;

  try
  {
    // ���� �޽��� ������ ���� CA/RA�� ������ & �����Ű�� ������
    recipCnK = AuthorityLoginProfile::get()->getMyCnK(_reqMessage->header->recipKID);
  }
  catch (exception)
  {
    recipCnK = AuthorityLoginProfile::get()->getMyCnK();
  }

  // 1.1. Header ����
  boost::shared_ptr<AlgorithmIdentifier> protectionAlg;
  Nid protectionAlgNid;

  // 1.1.1. protectionAlg ����
  /**
   * RFC 2510 draft bis04 3.3.21
   *  If protection is desired on the message, the client MUST protect it
   *  using the same technique (i.e., signature or MAC) as the starting
   *  message of the transaction.  The CA MUST always sign it with a
   *  signature key.
   *
   * RA�� ���ؼ��� protection ���� ����� ���� ����� �Ǿ� ���� �����Ƿ�,
   * RA�� ��û �޽����� ir�̰� ��û �޽����� protection ����� MAC�϶�,
   * MAC ���� �����ϱ� ���� secret value���� RA�� �˰� �ִ� ��쿡��
   * MAC �����, �׷��� ���� ��쿡�� ������ �̿��ϵ��� �Ѵ�.
   */
  //
  //  CA/RA
  //
  if (CALoginProfile::get())
  {
    // CA�� ��쿡�� �׻� signature ���
    protectionAlg.reset(ASN_New(AlgorithmIdentifier, NULL), ASN_Delete);
    protectionAlgNid =
      AlgNid_GetSigAlgNid(
        recipCnK.first->tbsCertificate->subjectPublicKeyInfo->
        algorithm->algorithm->nid, NID_SHA1);
    VERIFY(::AlgorithmIdentifier_SetNid(
      protectionAlg.get(),
      protectionAlgNid,
      recipCnK.first->tbsCertificate->
      subjectPublicKeyInfo->algorithm->parameters) == SUCCESS);
  }
  else
  {
    // RA
    if (_reqMessage->body->select == PKIBody_ir &&
      _reqMessage->header->protectionAlg->algorithm->nid == NID_passwordBasedMac &&
      _senderAuthInfo.get() != NULL)
    {
      protectionAlg.reset(
        reinterpret_cast<AlgorithmIdentifier *>(
          ASN_Dup(ASN(_reqMessage->header->protectionAlg))),
        ASN_Delete);
    }
    else
    {
      protectionAlg.reset(ASN_New(AlgorithmIdentifier, NULL), ASN_Delete);
      protectionAlgNid =
        AlgNid_GetSigAlgNid(
          recipCnK.first->tbsCertificate->subjectPublicKeyInfo->algorithm->algorithm->nid,
          NID_SHA1);
      VERIFY(::AlgorithmIdentifier_SetNid(
        protectionAlg.get(),
        protectionAlgNid,
        recipCnK.first->tbsCertificate->subjectPublicKeyInfo->algorithm->parameters) == SUCCESS);
    }
  }

  boost::shared_ptr<PKIHeader> pkiHeader(ASN_New(PKIHeader, NULL), ASN_Delete);

  SubjectKeyIdentifier *certKeyid = Extensions_GetByType(
    NULL,
    recipCnK.first->tbsCertificate->extensions,
    SubjectKeyIdentifier,
    NID_subjectKeyIdentifier);

  ret = ::PKIMSG_MakePKIHeader(
    pkiHeader.get(),
    _reqMessage->header->recipient->choice.directoryName,
    _reqMessage->header->sender->choice.directoryName,
    0,
    protectionAlg.get(),
    certKeyid,
    _reqMessage->header->senderKID,
    _reqMessage->header->transactionID,
    NULL,
    _reqMessage->header->senderNonce);

  ASN_Del(certKeyid);

  if (ret != SUCCESS)
  {
    /*# ERROR : Header ���� ���� */
  }

  // 1.2. Body ����
  boost::shared_ptr<PKIBody> pkiBody(ASN_New(PKIBody, NULL), ASN_Delete);
  VERIFY(::ASNChoice_Select(ASN_CHOICE(pkiBody.get()), PKIBody_error) == SUCCESS);

  /*# FIXME : Memory copy ȸ�� ���̱�.. */
  ASN_Copy(pkiBody->choice.error, content);

  // 1.3. �޽��� ����
  boost::shared_ptr<PKIMessage> errMsg(
    ASN_New(PKIMessage, NULL), ASN_Delete);

  //
  //  CA
  //
  if (CALoginProfile::get())
  {
    ret = ::CMP_MakePKIMessage(
      errMsg.get(),
      pkiHeader.get(), pkiBody.get(),
      recipCnK.second.get(), recipCnK.first.get(),
      NULL, /* ������ Ȥ�� �����Ű ���� domain parameter�� �ݵ�� �� ����.*/
      NULL, 0,
      NULL);
  }
  //
  //  RA
  //
  else
  {
    if (protectionAlg->algorithm->nid == NID_passwordBasedMac)
    {
      char buf[MAX_SECRETVAL_LEN];
      VERIFY(::ASNOctStr_Get(buf, sizeof(buf),
        _senderAuthInfo->choice.secretValue->secretValue) != FAIL);
      ret = ::CMP_MakePKIMessage(
        errMsg.get(),
        pkiHeader.get(), pkiBody.get(),
        NULL, NULL, NULL,
        buf, ::strlen(buf),
        NULL);
    }
    else
    {
      ret = ::CMP_MakePKIMessage(
      errMsg.get(),
      pkiHeader.get(), pkiBody.get(),
      recipCnK.second.get(), recipCnK.first.get(),
      NULL, /* ������ Ȥ�� �����Ű ���� domain parameter�� �ݵ�� �� ����.*/
      NULL, 0,
      NULL);
    }
  }

  if (ret != SUCCESS)
  {
    /*# ERROR : ���� �޽��� ���� ���� */
    return;
  }

  try
  {
    _sock.sendPKIMessage(errMsg.get());
  }
  catch (...)
  {
  }
}

void CMP::sendResMessage()
{
  try
  {
    _sock.sendPKIMessage(_resMessage.get());
  }
  catch (Exception &e)
  {
    CMPException e(LOG_CAMSGD_FAIL_TO_SEND_RESPONSE_N);
    e.addOpt("���� �޽����� PKIBody�� choice ��",
      _resMessage->body->select - 1);
    throw e;
  }
}

void CMP::recvReqMessage()
{
  _reqMessage.reset(_sock.recvPKIMessage(), ASN_Delete); // receive reqMessage
}

void CMP::removeRefnum()
{
  try
  {
    dynamic_cast<Issac::DB::DBSubject *>(_sender.get())->getDefaultCert();
  }
  catch (Exception)
  {
    // ������� default �������� �߱޵��� ���� ��쿡��
    // reference number�� �������� ����
    return;
  }

  try
  {
    _senderAuth.get()->remove();
  }
  catch (DBCommandException)
  {
    /*# ERROR : Reference number ���� ���� */
    /*# LOG : Reference number ���� ���� */
    CMPException e(LOG_CAMSGD_FAIL_TO_REMOVE_REFNUM_N);
    e.addOpt(
      "Reference number",
      dynamic_cast<Issac::DB::DBAuth*>(_senderAuth.get())->getRefNum());
    throw e;
  }
}

//typedef std::vector<CCommandContextPtr> CCommandContextPtrVector;

void CMP::revokeUnconfirmedCerts()
{
  for (vector<ISSUE_CONTEXT>::iterator i = _issueCtx.begin();
    i != _issueCtx.end(); i++)
  {
    try
    {
      DBPKC *pkc = dynamic_cast<DBPKC*>(i->pkc.get());
      pkc->revoke(DBObjectBase::getSelf(), CRLReason_cessationOfOperation);
      /*# LOG : �߱޵� ������ ���� */
    }
    catch (DBException)
    {
      /*
        "ERROR : Conf �޽��� ���� ���з� ���� �߱޵� �������� �����ϴµ� ����\n"
        "LOG : �������� �߱޵� ������ �������� ������ �߻��Ͽ�, "
        "�߱޵� �������� �����ϴµ� ����"
        */
    }
  }
}

/**
 * �� function������ PKIMessage�� body�� �ؼ��ؼ�
 * ���� �޽����� body(_responseBody)�� �����Ѵ�.
 */
void CMP::dispatchAndProcessRequest()
{
  switch (_reqMessage->body->select)
  {
  case PKIBody_ir : // Initialization request
  case PKIBody_cr : // Certification request
  case PKIBody_kur : // Key update request
  case PKIBody_ccr : // Cross-Cert. request
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    processCertRequest();
    break;
  /*
  case PKIBody_p10cr: // PKCS #10 Cert. Req.
    break;
  case PKIBody_popdecc: // POP challenge
    break;
  case PKIBody_popdecr: // POP response
    break;
  case PKIBody_krr: // Key recovery request
    break;
  */
  case PKIBody_rr :  // Revocation request
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    processRevokeRequest();
    break;
  case PKIBody_conf :  // Confirmation
    break;
  /*
  case PKIBody_nested:  // Nested message
    break;
  */
  case PKIBody_genm :  // General message
    processGeneralMsg();
    break;
  /*
  case PKIBody_error:  // Error message
    break;
  */
  default :
    {
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    /*# ERROR: Invalid message */
    /*# LOG : �������� �ʴ� ��û */
    CMPSendErrorException e(LOG_CAMSGD_UNSUPPORTED_REQUEST_N);
    e.addOpt("PKIBody�� choice ��", _reqMessage->body->select - 1);
    throw e;
    }
    break;
  }
}

void CMP::makeResMessage()
{
  // 1. Header ����
  boost::shared_ptr<PKIHeader> pkiHeader(ASN_New(PKIHeader, NULL), ASN_Delete);

  AlgorithmIdentifier *protectionAlg;

  switch (_senderAuthInfo->select)
  {
  case PKISenderAuthInfo_secretValue :
  case PKISenderAuthInfo_revPassPhrase :
    protectionAlg = reinterpret_cast<AlgorithmIdentifier *>(
      ASN_Dup(ASN(_reqMessage->header->protectionAlg)));
    break;

  case PKISenderAuthInfo_certAndPriKey :
  default:
    protectionAlg = ASN_New(AlgorithmIdentifier, NULL);
    Nid nidProtection = ::AlgNid_GetSigAlgNid(
      _recipCnK.first->tbsCertificate->
      subjectPublicKeyInfo->algorithm->algorithm->nid,
      NID_SHA1);
    /*# NOTE : ���� CA(2.3)�� RA���� Parameter�� �� ���� ���� �������� ����ϴ� ��츦 ���� ó�� */
    Parameter *param;
    if (_recipCnK.first->tbsCertificate->subjectPublicKeyInfo->algorithm->parameters != NULL)
      param = _recipCnK.first->tbsCertificate->subjectPublicKeyInfo->algorithm->parameters;
    else if (_recipCnK.second->privateKeyAlgorithm->parameters != NULL)
      param = _recipCnK.second->privateKeyAlgorithm->parameters;
    else
      param = NULL;
    VERIFY(::AlgorithmIdentifier_SetNid(
      protectionAlg, nidProtection, param) == SUCCESS);
    break;

  }
  int ret = ::PKIMSG_MakePKIHeader(
    pkiHeader.get(),
    _reqMessage->header->recipient->choice.directoryName,
    _reqMessage->header->sender->choice.directoryName,
    0,
    protectionAlg,
    _reqMessage->header->recipKID,
    _reqMessage->header->senderKID,
    _reqMessage->header->transactionID,
    NULL/* Sender Nonce: ���ο��� �ڵ����� ������*/,
    _reqMessage->header->senderNonce);
  ASN_Del(protectionAlg);

  if (ret != SUCCESS)
  {
    /*# ERROR : PKIMessage ���� ���� */
    /*# LOG : ���� �޽����� Header ���� ���� */
    throw CMPSendErrorException(LOG_CAMSGD_FAIL_TO_MAKE_RESPONSE_HEADER_N);
  }

  // 2. Protection ���� �� Message ����
  _resMessage.reset(ASN_New(PKIMessage, NULL));
  char buf[MAX_SECRETVAL_LEN];
  switch (_senderAuthInfo.get()->select)
  {
  case PKISenderAuthInfo_secretValue :
    // 2.1. MAC���� Protection ����
    VERIFY(ASNOctStr_Get(
      buf, sizeof(buf),
      _senderAuthInfo.get()->choice.secretValue->secretValue) != FAIL);
    ret = ::CMP_MakePKIMessage(
      _resMessage.get(), pkiHeader.get(), _resBody.get(),
      NULL, NULL, NULL,
      buf, ::strlen(buf),
      NULL);
    break;
  case PKISenderAuthInfo_certAndPriKey :
    // 2.2. �������� Protection ����
    ret = ::CMP_MakePKIMessage(
      _resMessage.get(), pkiHeader.get(), _resBody.get(),
      _recipCnK.second.get(), _recipCnK.first.get(), NULL,
      NULL, 0,
      NULL);
    break;
  case PKISenderAuthInfo_revPassPhrase :
    // 2.3. MAC���� Protection ����
    VERIFY(ASNOctStr_Get(
      buf, sizeof(buf),
      _senderAuthInfo.get()->choice.revPassPhrase->revPassPhrase) != FAIL);
    ret = ::CMP_MakePKIMessage(
      _resMessage.get(), pkiHeader.get(), _resBody.get(),
      NULL, NULL, NULL,
      buf, ::strlen(buf),
      NULL);
    break;
  default:
    VERIFY(false);
  }

  if (ret != SUCCESS)
  {
    /*# ERROR : PKIMessage ���� ���� */
    /*# LOG : ���� �޽��� ���� ���� */
    CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_MAKE_RESPONSE_MESSAGE_N);
    e.addOpt(
      "������ ���� �޽����� Header(DER Encoded)",
      reinterpret_cast<ASN *>(pkiHeader.get()));
    throw e;
  }
}

std::string CMP::getLogReqInfo(
          boost::shared_ptr<Issac::DB::DBObjectBase> requester,
          std::string peerName)
{
  DBSubject *subject =
    dynamic_cast<DBSubject*>(requester.get());
  DBEntity  *entity =
    dynamic_cast<DBEntity*>(requester.get());

  std::ostringstream ost;

  ost << peerName << ";"
    << ( subject ? subject->getDN() : "" ) << ";"
    << ( entity ? (entity->id) : "" ) << ";"
    << ( subject ? subject->getType() : "") << ";";

  return ost.str();
}

std::string CMP::getLogHolderInfo(
    boost::shared_ptr<Issac::DB::DBObjectBase> certHolder)
{
  ostringstream ost;

  DBSubject *subject =
    dynamic_cast<DBSubject*>(certHolder.get());
  DBEntity *entity =
    dynamic_cast<DBEntity*>(certHolder.get());

  ost << (subject ? subject->getDN() : "") << ";"
    << (entity ? (entity->id) : "");

  return ost.str();
}

}
