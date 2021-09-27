/**
 * @file    CMP_issueCert_CA.hpp.cpp
 *
 * @desc    �������� �߱� Ȥ�� CA�� �߱� ��û ������ �ϴ� function
 * @author   ������(hrcho@pentasecurity.com)
 * @since    2002.05.01
 *
 * Revision History
 *
 * @date     2002.05.02 : Start
 *
 *
 */

// standard headers
#include <sstream>
#include <cassert>
#include <boost/cast.hpp>
#include <boost/scoped_array.hpp>

// cis headers
#include "pkimessage.h"
#include "rand_ansi.h"
#include "sha1.h"

#include "Trace.h"

// pki headers
#include "DBObject.hpp"
#include "DBSubject.hpp"
#include "DBPolicy.hpp"
#include "DBPKC.hpp"
#include "cis_cast.hpp"
#include "CMPSocket.hpp"
#include "Log.hpp"
#include "CnK_define.hpp"
#include "CertHelper.h"
#include "CertHelper.h"

#include "CALoginProfile.hpp"
#include "RALoginProfile.hpp"
#include "CMP.hpp"
#include "CMPException.hpp"
#include "PKILogTableDefine.hpp"

using namespace Issac::DB;
using namespace std;

#define TMPLOG "/tmp/cmp.log"

namespace Issac
{

/**
 *  ������ �߱� ��û �޽���(ir, kur, cr, ccr) ó�� ������ ������ ����.
 *  1. CA�� ���
 *    1) �߱޿� ���� ������ ��å�� ������
 *    2) ������ ��û �޽����� �ùٸ� ������ ������ �ְ�, ��å�� �����ϴ��� Ȯ��
 *    3) ������ ����
 *    4) ������ �������� DB�� ����
 *    5) ���� �޽��� ����
 *  2. RA�� ���
 *    1) �߱޿� ���� ������ ��å�� ������
 *    2) ������ ��û �޽����� �ùٸ� ������ ������ �ְ�, ��å�� �����ϴ��� Ȯ��
 *    3) '2)'���� ������ ��û�� ���ؼ� CA���� ������ �߱��� ��û
 *      - ��û�ڷκ��� ������ ��û �޽����� �����Ͽ� CA���� ���� ��û �޽����� ����
 *      - CA���� ��û �޽��� ����
 *      - CA�κ��� ���� �޽��� ����
 *    4) CA�κ��� ���ŵ� �߱޵� ���������� DB�� ����
 *      - ���� �޽��� ���� ��, �ش� ������ �̿��Ͽ� ���� �޽��� ����
 *    5) ���� �޽��� ����
 */

//////////////////////////////////////////////////////////////////////
// CMPIssueCertificate Class
//////////////////////////////////////////////////////////////////////

void CMP::issueCerts()
{
  // Memory ó���� ȿ������ ���̱� ���� PKIMessage����
  // CertReqMsg�� �������� �ʰ� �ణ�� �Ǽ�(?)�� ���.
  // �Ϲ������δ� ASN_Dup���� ����Ͽ� element�� ������ ��,
  // ���� ������ element�� context item���� setting�ؾ� �ϳ�
  // (���縦 ���� ������ �� context�� ������ 2�� free�ϰ� ��)
  // ���⿡���� PKIMessage���� CertReqMessages�� size�� 0���� setting�Ͽ�
  // PKIMessage�κ��� context�� pointer�� �������� ���� �̵���Ű�� ����� ����Ͽ���.

  CertReqMessages *certReqMessages = _reqMessage->body->choice.ir;
  int reqIdx;
  int reqCount = certReqMessages->size; // stores original size
  certReqMessages->size = 0;         // discards ownship of pointers

  // 1. ������ �߱� ������ ��û �޽��� �˻� & �ؼ�
  for (reqIdx = 0; reqIdx < reqCount; ++reqIdx)
  {
    ISSUE_CONTEXT ctx;
    // FIXME - �Ʒ��� �ڵ�� stl Ư���� �ݺ��� �޸� ����� ���� ���ϴ�.
    // ������ �߰��� ������ ������ �ε��� ���� �����ϱ� ���ؼ���
    // �������� push_back�� ���� �ʰ� �̸� �ְ� �ε����ߴ�.
    // �ݵ�� �׷��� �ϴ� ���� �ƴ�����...
    _issueCtx.push_back(ctx);
    _issueCtx[reqIdx].certHolder = _certHolder;
    _issueCtx[reqIdx].reqIndex = reqIdx;
    _issueCtx[reqIdx].certReqMsg.reset(certReqMessages->member[reqIdx], ASN_Delete);
    _issueCtx[reqIdx].reqType = static_cast<int>(_reqMessage->body->select);

    try
    {
      // verify validity
      resolveCertReqMsg(_issueCtx[reqIdx]);
      getIssueInfo(_issueCtx[reqIdx]);
      checkPolicy(_issueCtx[reqIdx]);
    }
    catch (CMPException &e)
    {
      LogItemSharedPtr logItem(AuthorityLoginProfile::get()->getLog()->createLogItem());

      logItem->setLogItem(e.getCode(), e.getOpts());
      logItem->setRequester(getLogReqInfo(_sender, _sock.getPeerName()));
      //logItem->setWorker(DBObjectBase::getSelf());
      logItem->setCertHolder(getLogHolderInfo(_certHolder));
      logItem->write();

      // error response ����
      VERIFY(e.getErrorMsgContent());
      CertResponse *errorResponse = ASN_New(CertResponse, NULL);

      ASN_Copy(
        errorResponse->certReqId,
        certReqMessages->member[reqIdx]->certReq->certReqId);
      ASN_Copy(
        errorResponse->status,
        e.getErrorMsgContent()->pKIStatusInfo);

      _issueCtx[reqIdx].certResponse.reset(errorResponse, ASN_Delete);
    }
  }

  // 2. ������ �߱�
  if (CALoginProfile::get())
    makeCerts();
  else
    recvCertsFromCA();

  // 3. certResponse ����
  makeCertResponse();

  // 4. ���� �޽��� body ����
  _resBody.reset(ASN_New(PKIBody, NULL), ASN_Delete);

  switch (_reqMessage->body->select)
  {
  case PKIBody_ir :
    ASNChoice_Select(ASN_CHOICE(_resBody.get()), PKIBody_ip);
    break;
  case PKIBody_cr :
    ASNChoice_Select(ASN_CHOICE(_resBody.get()), PKIBody_cp);
    break;
  case PKIBody_kur :
    ASNChoice_Select(ASN_CHOICE(_resBody.get()), PKIBody_kup);
    break;
  case PKIBody_ccr :
    ASNChoice_Select(ASN_CHOICE(_resBody.get()), PKIBody_ccp);
    break;
  default :
    VERIFY(false);
  }

  // response�� caPubs �ʵ� ����
  /*# FIXME : CA�� NewWithOld, OldWithNew�� �߰��ϴ� ���� ����� �� */
  /*# FIXME : ����ڰ� �ֽ� �������� ������ �ִ��� �Ǵ��ϴ� ����� �������� */
  if (_recipCnK.first.get() !=
    AuthorityLoginProfile::get()->getMyCnK().first.get())
  {
    // ����ڰ� ������ CA �������� ������ �ִ� ���
    // union�̱� ������ ip, cp, ccp, kup�� ��� ����
    VERIFY(::ASNSeq_NewOptional(
      pASN(&_resBody->choice.ip->caPubs),
      ASN_SEQ(_resBody->choice.ip)) == SUCCESS);
    VERIFY(::ASNSeqOf_Add(
      ASN_SEQOF(_resBody->choice.ip->caPubs),
      ASN(AuthorityLoginProfile::get()->getCACerts().begin()->get())) == SUCCESS);
  }
  else if (_senderAuthInfo->select == PKISenderAuthInfo_secretValue)
  {
    // ����ڰ� MAC protection�� ����Ͽ� ��û �޽����� �ۼ��� ���
    // union�̱� ������ ip, cp, ccp, kup�� ��� ����
    VERIFY(::ASNSeq_NewOptional(
      pASN(&_resBody->choice.ip->caPubs),
      ASN_SEQ(_resBody->choice.ip)) == SUCCESS);
    VERIFY(::ASNSeqOf_Add(
      ASN_SEQOF(_resBody->choice.ip->caPubs),
      ASN(AuthorityLoginProfile::get()->getCACerts().begin()->get())) == SUCCESS);
  }

  for (vector<ISSUE_CONTEXT>::iterator i = _issueCtx.begin();
     i != _issueCtx.end(); i++)
  {
    // union�̱� ������ ip, cp, ccp, kup�� ��� ����
    // memory copy ȸ���� ���̱� ���� shared_ptr�� �������� ���������� ������ ���� ����?
    // �� conf ó���ÿ��� certResponse�� ����ϹǷ� ������ ��
    VERIFY(::ASNSeqOf_Add(
      ASN_SEQOF(_resBody->choice.ip->response),
      ASN(i->certResponse.get())) == SUCCESS);
  }
}

void CMP::getIssueInfo(ISSUE_CONTEXT &ctx)
{
  // DB�κ��� ������ �������� �����´�.
  // 1. ������ �߱޿� �ʿ��� ������ ��å
  // 2. ��ȣ ���� ������ Ȥ�� Ű ������ ���� �ʴ� ������ ���� �ÿ�
  //    ��ü Ű �ĺ��ڰ� ���� ������ �����ǵ��� �ϱ� ���� ���� �������� ��ü Ű �ĺ��� ��

  DBSubject *certHolder = dynamic_cast<DBSubject*>(ctx.certHolder.get());

  boost::shared_ptr<OctetString> policySid;
  boost::shared_ptr<OldCertId> oldCertId;

  if (ctx.certReqMsg->certReq->controls != NULL)
  {
    policySid.reset(
      Controls_GetByType(
        ctx.certReqMsg->certReq->controls,
        OctetString, NID_penta_at_cmp_keyPolicyId),
      ASN_Delete);
    oldCertId.reset(
      Controls_GetByType(
        ctx.certReqMsg->certReq->controls, OldCertId, NID_oldCertID),
      ASN_Delete);
  }

  if (policySid.get() != NULL)
  {
    // ��û �޽��� ���� SID�� �����Ǿ� �ִ� ���, �ش� ������ policy ���� ����
    // �ش� policy�� ����ڿ��� �Ҵ�Ǿ� �ִ��� Ȯ��
    char sid[64];
    VERIFY(::ASNOctStr_Get(
      sid, sizeof(sid), policySid.get()) != FAIL);
    ctx.policy = certHolder->getPolicy(sid);
  }
  else if (ctx.reqType == PKIBody_kur && oldCertId.get() != NULL)
  {
    // key update�� ��� �޽��� �ȿ� oldCertId�� ������ �� ������ policy���� ����
    DBEntity *entity;
    DBAuthority *authority;

    char serNum[100];

    std::ostringstream ost;
    VERIFY(::ASNInt_GetStr(
      serNum, sizeof(serNum), oldCertId->serialNumber) != FAIL);
    if ((entity = dynamic_cast<DBEntity*>(certHolder)) != NULL)
    {
      boost::shared_ptr<DBEntityPKC> pkc;
      ost <<
        "SER='" << serNum << "' AND " <<
        "ESID='" << entity->sid << "'";

      try
      {
        pkc = Issac::DB::selectEx<DBEntityPKC>(ost.str().c_str());
      }
      catch (DBSelectException)
      {
        // �߸��� certId
        /*# LOG : �߸��� oldCertId �� */
        CMPSendErrorException e(LOG_CAMSGD_BAD_OLDCERTID_N);
        e.addOpts(
          "�ش� certReqMsg�� index(0����) : %i, oldCertId�� serialNumber �� : %s",
          ctx.reqIndex, serNum);
        throw e;
      }

      // ������ �߱� ��û ���� ����Ű�� ������ �������� ����Ű�� ���� ���
      // ���� �������κ��� KID���� ������
      boost::shared_ptr<Certificate> cert;
      try
      {
        cert = pkc->getCertificate();
        getPreviousKeyId(ctx.reqCertInfo.get(), cert.get());
      }
      catch (Exception) {} // ignored

      try
      {
        ctx.policy = certHolder->getPolicy(pkc->psid);
      }
      catch (DBSelectException)
      {
        // DB �������� ����
        /*# LOG : �߱��� ���� ����� ���� �������� ���� */
        CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_GET_SUBJECT_INFO_N);
        e.addOpt("�߱� ��� DN", entity->dn);
        throw e;
      }
    }
    else
    {
      authority =
        boost::polymorphic_downcast<DBAuthority *>(certHolder);
      boost::shared_ptr<DBAuthorityPKC> pkc;
      ost <<
        "SER='" << serNum << "' AND " <<
        "ASID='" << authority->sid << "'";

      try
      {
        pkc = selectEx<DBAuthorityPKC>(ost.str().c_str());
      }
      catch (DBSelectException)
      {
        // �߸��� certId
        /*# LOG : �߸��� oldCertId �� */
        CMPSendErrorException e(LOG_CAMSGD_BAD_OLDCERTID_N);
        e.addOpts(
          "�ش� certReqMsg�� index(0����) : %i, oldCertId�� serialNumber �� : %s",
          ctx.reqIndex, serNum);
        throw e;
      }
      // ������ �߱� ��û ���� ����Ű�� ������ �������� ����Ű�� ���� ���
      // ���� �������κ��� KID���� ������
      boost::shared_ptr<Certificate> cert;
      try
      {
        cert = pkc->getCertificate();
        getPreviousKeyId(ctx.reqCertInfo.get(), cert.get());
      }
      catch (Exception) {} // ignored

      try
      {
        ctx.policy = certHolder->getPolicy(authority->psid);
      }
      catch (DBSelectException)
      {
        // DB �������� ����
        /*# LOG : �߱��� ���� ����� ���� �������� ���� */
        CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_GET_SUBJECT_INFO_N);
        e.addOpt("�߱� ��� DN", authority->dn);
        throw e;
      }
    }
  }
  else if (ctx.reqType == PKIBody_cr)
  {
    // cr�� ��쿡�� ����ڿ��� �������� �߱޵��� ���� policy�鿡 ���ؼ� ������ �߱�
    try
    {
      ctx.policy = certHolder->getUnusedPolicy(ctx.reqIndex);
    }
    catch (Exception)
    {
      // ����ڿ��� �������� �߱޵��� ���� policy�� ������ ��û �������� ����
      /*# LOG : �߱��� ��û�ϴ� �������� ������ ����ڿ��� �����Ǿ� �ִ� ������ ��ġ���� ���� */
      /*# FIXME : �ܼ��� policy�� �������µ� ������ ����� ���� �����Ƿ� ������ ��...*/
      CMPSendErrorException e(LOG_CAMSGD_INCORRECT_NUM_OF_CERTREQ_N);
      e.addOpts(
        "PKIBody�� choice �� : %i, �ش� certReqMsg�� index(0����) : %i",
        ctx.reqType - 1, ctx.reqIndex);
      throw e;
    }
  }
  else
  {
    // �� �̿��� ��쿡�� ����ڿ��� mapping�Ǿ� �ִ� policy ������� ������
    // FIXME : kur�� ��쿡��?
    try
    {
      ctx.policy = certHolder->getPolicy(ctx.reqIndex);
    }
    catch (DBSelectException)
    {
      // ����ڿ��� �������� �߱޵��� ���� policy�� ������ ��û �������� ����
      /*# LOG : �߱��� ��û�ϴ� �������� ������ ����ڿ��� �����Ǿ� �ִ� ������ ��ġ���� ���� */
      /*# FIXME : �ܼ��� policy�� �������µ� ������ ����� ���� �����Ƿ� ������ ��...*/
      CMPSendErrorException e(LOG_CAMSGD_INCORRECT_NUM_OF_CERTREQ_N);
      e.addOpts(
        "PKIBody�� choice �� : %i, �ش� certReqMsg�� index(0����) : %i",
        ctx.reqType - 1, ctx.reqIndex);
      throw e;
    }
  }

  // ��ȣ ���� ������ ��û�� ��쿡 ��ü Ű �ĺ��� ��������
  if (ctx.reqType == PKIBody_ccr)
  {
    boost::shared_ptr<DBAuthorityPKC> pkc;
    std::ostringstream ost;

    DBAuthority *authority =
      boost::polymorphic_downcast<DBAuthority *>(certHolder);
    DBAuthority *ca =
      boost::polymorphic_downcast<DBAuthority *>(
        DBObjectBase::getCA().get());
    ost <<
      "ASID='" << authority->sid << "' AND " <<
      "(ISSUERDN IS NULL OR ISSUERDN='' OR ISSUERDN!='" << ca->sid << '\'' <<
      "ORDER BY CDATE DESC";
    try
    {
      pkc = Issac::DB::selectEx<DBAuthorityPKC>(ost.str().c_str());
    }
    catch (DBSelectException)
    {
      /*# Exception : ��ȣ ���� ����� �������� ���� */
      /*# LOG : �������� �߱��� ��ȣ ��������� �������� DB�� �� ���� ���� */
      CMPSendErrorException e(LOG_CAMSGD_NO_CROSSCA_CERT_N);
      e.addOpt("�ش� certReqMsg�� index(0����)", ctx.reqIndex);
      throw e;
    }

    boost::shared_ptr<Certificate> cert;
    try
    {
      cert = pkc->getCertificate();
      getPreviousKeyId(ctx.reqCertInfo.get(), cert.get());
    }
    catch (Exception) { } // ignored
  }
}

void CMP::getPreviousKeyId(PKIReqCertInfo *reqCertInfo, Certificate *prevCert)
{
  VERIFY(reqCertInfo && prevCert);

  if (reqCertInfo == NULL || prevCert == NULL) return;

  // ���� �������� SubjectKeyIdentifier�� ����
  if (prevCert->tbsCertificate->extensions == NULL) return;

  // 1. ����Ű ���� ������ ��
  boost::shared_ptr<ASNBuf> recvedPubKeyBuf(
      ASN_EncodeDER(reqCertInfo->publicKey),
      ASNBuf_Delete);
  boost::shared_ptr<ASNBuf> storedPubKeyBuf(
      ASN_EncodeDER(prevCert->tbsCertificate->subjectPublicKeyInfo),
      ASNBuf_Delete);

  if (recvedPubKeyBuf->len != storedPubKeyBuf->len ||
    recvedPubKeyBuf->len == 0 ||
    ::memcmp(recvedPubKeyBuf->data, storedPubKeyBuf->data, recvedPubKeyBuf->len) != 0)
    return;

  SubjectKeyIdentifier *keyid = Extensions_GetByType(
    NULL, prevCert->tbsCertificate->extensions,
    SubjectKeyIdentifier, NID_subjectKeyIdentifier);

  if (keyid != NULL)
    VERIFY(::ASNSeq_NewSetPOptional(
      pASN(&reqCertInfo->subjectKeyId), ASN_SEQ(reqCertInfo),
      ASN(keyid)) == SUCCESS);
}

void CMP::checkPolicy(ISSUE_CONTEXT &ctx)
{
  int ret;

  DBPolicy *policy = boost::polymorphic_downcast<DBPolicy *>(
    ctx.policy.get());

  // 1. ����Ű �� �˻�
  if (ctx.reqCertInfo->publicKey != NULL)
  {
    // 1.1. ����Ű �˰��� �˻�
    if (ctx.reqCertInfo->publicKey->algorithm->algorithm->nid !=
      string2type<Nid>(policy->tpubalg))
    {
      /*# Exception : �߸��� ����Ű �˰��� */
      CMPSendErrorException e(LOG_CAMSGD_WRONG_PUBLICKEY_ALG_N);
      e.addOpts(
        "�ش� certReqMsg�� index(0����) : %i, "
        "��û �޽��� ���� ����Ű �˰����� OID : %o, "
        "��å �� : %s",
        ctx.reqIndex,
        &ctx.reqCertInfo->publicKey->algorithm->algorithm->oid,
        policy->name.c_str());
      throw e;
    }

    // 1.2. ����Ű ���� �˻�
    int keyBitLen;
    ret = CERT_GetKeyBitLength(&keyBitLen, ctx.reqCertInfo->publicKey);
    if (ret != SUCCESS)
    {
      /*# Exception : �߸��� ����Ű ���� */
      CMPSendErrorException e(LOG_CAMSGD_WRONG_PUBLICKEY_LEN_N);
      e.addOpts(
        "�ش� certReqMsg�� index(0����) : %i, "
        "��å �� : %s",
        ctx.reqIndex, policy->name.c_str());
      throw e;
    }

    if (keyBitLen != policy->tpublen)
    {
      /*# Exception : �߸��� ����Ű ���� */
      CMPSendErrorException e(LOG_CAMSGD_WRONG_PUBLICKEY_LEN_N);
      e.addOpts(
        "�ش� certReqMsg�� index(0����) : %i, "
        "��û �޽��� ���� ����Ű ���� : %i, "
        "��å �� : %s",
        ctx.reqIndex, keyBitLen, policy->name.c_str());
      throw e;
    }

    // 1.3. ������ �Ķ���� �˻�
    if (policy->pqg.len != 0)
    {
      ASNBuf domainParamBuf;
      ASNBuf_SetP(&domainParamBuf, policy->pqg.data, policy->pqg.len);
      boost::shared_ptr<Parameter> pDomainParam(ASN_New(Parameter, &domainParamBuf), ASN_Delete);
      if (pDomainParam.get() == NULL)
      {
        /*# ERROR : �߸��� DB ���� ������ �Ķ���� �� */
        /*# LOG : DB���� ������ �Ķ���� ���� �ùٸ��� ���� */
        CMPSendErrorException e(LOG_CAMSGD_INVALID_DOMAINPARAM_IN_DB_N);
        e.addOpts(
          "�ش� certReqMsg�� index(0����) : %i, ��å �� : %s",
          ctx.reqIndex, policy->name.c_str());
        throw e;
      }

      if (ctx.reqCertInfo->publicKey->algorithm->parameters != NULL)
      {
        if (::Parameter_Compare(
          ctx.reqCertInfo->publicKey->algorithm->parameters,
          pDomainParam.get(),
          ctx.reqCertInfo->publicKey->algorithm->algorithm->nid) != SUCCESS)
        {
          /*# ERROR : �߸��� ������ �Ķ���� �� */
          /*# LOG : ����Ű �˰��� ���� ������ �Ķ���� ���� �������� ��ġ���� ���� */
          CMPSendErrorException e(LOG_CAMSGD_WRONG_DOMAINPARAM_N);
          e.addOpts(
            "�ش� certReqMsg�� index(0����) : %i, "
            "��û �޽��� ���� ������ �Ķ����(DER Encoded) : %a, "
            "��å �� : %s",
            ctx.reqIndex,
            ctx.reqCertInfo->publicKey->algorithm->parameters,
            policy->name.c_str());
          throw e;
        }
      }
      else
      {
        // ������ �Ķ���͸� �־� ��
        VERIFY(::ASNSeq_NewOptional(
          pASN(&ctx.reqCertInfo->publicKey->algorithm->parameters),
          ASN_SEQ(ctx.reqCertInfo->publicKey->algorithm)) == SUCCESS);
        ASN_Copy(
          ctx.reqCertInfo->publicKey->algorithm->parameters, pDomainParam.get());
      }
    }
  } // else : Ű���� CA���� �����ϴ� ���

  // 2. �����Ű ���� ���� �˻�
  if (!policy->krsid.empty())
  {
    if (ctx.reqCertInfo->publicKey != NULL &&
      ctx.reqCertInfo->privateKey == NULL)
    {
      /*# Exception : �����Ű�� �����ؾ� �Ǵµ� ���޵��� ���� */
      CMPSendErrorException e(LOG_CAMSGD_MISSING_PRIVATEKEY_N);
      e.addOpt("�ش� certReqMsg�� index(0����)", ctx.reqIndex);
      throw e;
    }
  }
}

//////////////////////////////////////////////////////////////////////
// CMPResolveCertReqMsgCommand Class
//////////////////////////////////////////////////////////////////////
void CMP::resolveCertReqMsg(ISSUE_CONTEXT &ctx)
{
  // PKIReqCertInfo *reqCertInfo = ASN_New(PKIReqCertInfo, NULL);
  ctx.reqCertInfo.reset(ASN_New(PKIReqCertInfo, NULL), ASN_Delete);

  // 1. CertReqMsg���� certReq�� certTemplate field ������ �ùٸ��� �˻�
  checkCertTemplate(ctx);
  // 2. CertReqMsg�� pop �˻� & �ؼ�
  verifyPOP(ctx);
  // 3. CertReqMsg���� certReq�� controls field ������ �ùٸ��� �˻� & �ؼ�
  checkControls(ctx);
}

void CMP::checkCertTemplate(ISSUE_CONTEXT &ctx)
{
  /* 1. certTemplate ���� �˻� */
  /*    1.1. version �˻� */
  int ver;
  if (ctx.certReqMsg->certReq->certTemplate->version != NULL)
  {
    int ret = ::ASNInt_GetInt(&ver, ctx.certReqMsg->certReq->certTemplate->version);
    if (ret != SUCCESS || ver < CERT_VER1 || CERT_VER2 > ver)
    {
      /*# Exception : �߸��� certTemplate version */
      CMPSendErrorException e(LOG_CAMSGD_INVALID_CERTTEMPLATE_VERSION_N);
      e.addOpts(
        "�ش� certReqMsg�� index(0����) : %i, certTemplate�� version : %i",
        ctx.reqIndex, ver);
      throw e;
    }
  }

  /*    1.2. issuer ���� �˻� */
  if (ctx.certReqMsg->certReq->certTemplate->issuer != NULL)
  {
    if (::Name_Compare(
      ctx.certReqMsg->certReq->certTemplate->issuer,
      AuthorityLoginProfile::get()->getMyCnK().first->tbsCertificate->subject) != 0)
    {
      /*# Exception : �߸��� certTemplate issuer */
      CMPSendErrorException e(LOG_CAMSGD_INVALID_CERTTEMPATE_ISSUER_N);
      e.addOpts(
        "�ش� certReqMsg�� index(0����) : %i, certTemplate�� issuer : %s",
        ctx.reqIndex,
        type2string<Name*>(ctx.certReqMsg->certReq->certTemplate->issuer).c_str());
      throw e;
    }
  }

  /*    1.3. signingAlg ���� �˻� */
  if (ctx.certReqMsg->certReq->certTemplate->signingAlg != NULL)
  {
    /*# FIXME : hash �˰����� SHA1���� ����. */
    if (::AlgNid_GetSigAlgNid(
      AuthorityLoginProfile::get()->getMyCnK().first->tbsCertificate->
      subjectPublicKeyInfo->algorithm->algorithm->nid, NID_SHA1) !=
      ctx.certReqMsg->certReq->certTemplate->signingAlg->algorithm->nid)
    {
      /*# Exception : �߸��� certTemplate signingAlg */
      CMPSendErrorException e(LOG_CAMSGD_INVALID_CERTTEMPLATE_SIGNALG_N);
      e.addOpts(
        "�ش� certReqMsg�� index(0����) : %i, certTemplate�� signingAlg OID : %o",
        ctx.reqIndex,
        &ctx.certReqMsg->certReq->certTemplate->signingAlg->algorithm->oid);
      throw e;
    }
  }

  /*    1.4. subject ���� �˻�(subject�� ���� ������ ������ �� �˻簡 �̷�����Ƿ� ����) */
  /*    1.5. publicKey ���� �˻�(POPȮ�� �� publicKey �˻絵 �̷�����Ƿ� ����), */
  /*    1.6. �׿�(serialNumber, issuerUID, subjectUID, validity���� CA�� ����) */
}

void CMP::verifyPOP(ISSUE_CONTEXT &ctx)
{
  DBSubject *sender = dynamic_cast<DBSubject *>(
    _sender.get());

  if (ctx.certReqMsg->certReq->certTemplate->publicKey == NULL &&
    ctx.certReqMsg->pop == NULL)
  {
    /* Ű���� CA���� �����ϴ� ��� */
  }
  else
  {
    PrivateKeyInfo *caPrivateKey, *oldCAPrivateKey;

    // POP ������ CA�� ����Ű�� ������� �����Ű�� ��ȣȭ �Ͽ� �����ϴ� ���,
    // CA�� ����Ű�� ���ŵ� ��쿡�� �� ����Ű�� ������ ����Ű �� ���
    // ������ ��ȣȭ �Ͽ� ���޵Ǿ������� �Ǵ��� ���� ���� ������,
    // �� ��쿡�� ������ ����Ű�� �����Ǵ� �����Ű�� POP ������ ������ ����.
    if (CALoginProfile::get())
    {
      CnKSharedPtrs cnKs(AuthorityLoginProfile::get()->getMyCnKs());
      CnKSharedPtrs::iterator i(cnKs.begin());
      caPrivateKey = i->second.get();
      ++i;
      oldCAPrivateKey =
        (i != cnKs.end()) ? i->second.get() : NULL;
    }
    else
      caPrivateKey = oldCAPrivateKey = NULL;

    char secretValue[MAX_SECRETVAL_LEN];
    int popTech;
    PublicKeyInfo *pubKey;
    PrivateKeyInfo *priKey;
    int ret;
    switch (_senderAuthInfo->select)
    {
    case PKISenderAuthInfo_secretValue :
      ret = ::CMP_VerifyPOP(
        &popTech, &pubKey, &priKey,
        ctx.certReqMsg.get(), caPrivateKey, NULL,
        secretValue);
      if (ret == ER_CMP_POP_FAIL_TO_DECRYPT &&
        oldCAPrivateKey != NULL)
        ret = ::CMP_VerifyPOP(
          &popTech, &pubKey, &priKey,
          ctx.certReqMsg.get(), caPrivateKey, NULL,
          secretValue);
      break;
    case PKISenderAuthInfo_certAndPriKey:
      ret = ::CMP_VerifyPOP(
        &popTech, &pubKey, &priKey,
        ctx.certReqMsg.get(), caPrivateKey, NULL,
        NULL);
      if (ret == ER_CMP_POP_FAIL_TO_DECRYPT &&
        oldCAPrivateKey != NULL)
        ret = ::CMP_VerifyPOP(
          &popTech, &pubKey, &priKey,
          ctx.certReqMsg.get(), caPrivateKey, NULL,
          NULL);
      break;
    default:
      VERIFY(false);
    }

    if (ret != SUCCESS && ret != ER_CMP_POP_CAPRIKEY_NOT_SUPPLIED)
    {
      /*# EXCEPTION : POP ���� ���� */
      /*# LOG : �����Ű�� POP(Proof of possesion) ���� ���� */
      CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_VERIFY_POP_N);
      e.addOpts(
        "�ش� certReqMsg�� index(0����) : %i, certReqMsg(DER Encoded) : %a",
        ctx.reqIndex, ctx.certReqMsg.get());
      throw e;
    }
    // POP ��� �˻�
    if (popTech == POP_Technique_RAVerified)
    {
      // sender�� ADMIN || RA �� ���� raVerified ���
      if (::strcmp(sender->getType().c_str(), PKIDB_ENTITY_TYPE_RA) != 0 &&
          ::strcmp(sender->getType().c_str(), PKIDB_ENTITY_TYPE_ADMIN) != 0)
      {
        /*# Exception : �㰡���� ���� POP ���(RAVerified) */
        /*# LOG : �㰡���� ���� POP ���(RAVerified) */
        CMPSendErrorException e(LOG_CAMSGD_POP_RAVERIFIED_NOT_ALLOWED_N);
        e.addOpt("�ش� ctx.certReqMsg�� index(0����)", ctx.reqIndex);
        throw e;
      }
    }

    VERIFY(::ASNSeq_NewOptional(
      pASN(&ctx.reqCertInfo->popTechnique), ASN_SEQ(ctx.reqCertInfo.get())) == SUCCESS);
    VERIFY(::ASNInt_SetInt(
      ctx.reqCertInfo->popTechnique, popTech) == SUCCESS);
    VERIFY(::ASNSeq_NewSetPOptional(
      pASN(&ctx.reqCertInfo->publicKey),
      ASN_SEQ(ctx.reqCertInfo.get()), ASN(pubKey)) == SUCCESS);
    if (priKey != NULL)
      VERIFY(::ASNSeq_NewSetPOptional(
        pASN(&ctx.reqCertInfo->privateKey),
        ASN_SEQ(ctx.reqCertInfo.get()), ASN(priKey)) == SUCCESS);
  }
}

void CMP::checkControls(ISSUE_CONTEXT &ctx)
{
  /* 1. certReq�� controls�� �ؼ� */
  if (ctx.certReqMsg->certReq->controls != NULL)
  {
    int i;
    for (i = 0; i < ctx.certReqMsg->certReq->controls->size; ++i)
    {
      /* 1.1. pkiArchiveOptions */
      if (ctx.certReqMsg->certReq->controls->member[i]->type->nid ==
        NID_pkiArchiveOptions)
      {
        /*# NOTE :  �̹� privateKey ���� ���� ���� pkiArchiveOptions�� ���� */
        if (ctx.reqCertInfo->privateKey != NULL) continue;

        ASNBuf *pkiArchiveOptsBuf;
        if (::ASNAny_Get(
          &pkiArchiveOptsBuf,
          ctx.certReqMsg->certReq->controls->member[i]->value) < 0)
        {
          /*# Exception : �߸��� pkiArchiveOptions �� */
          /*# LOG : pkiArchiveOptions �ؼ� ���� */
          CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_RESOLVE_PKIARCHIVEOPTS_N);
          e.addOpts(
            "�ش� certReqMsg�� index(0����) : %i, �ش� pkiArchivalOptions(DER Encoded) : %a",
            ctx.reqIndex,
            ctx.certReqMsg->certReq->controls->member[i]->value);
          throw e;
        }
        boost::shared_ptr<PKIArchiveOptions> pkiArchiveOpts(
          ASN_New(PKIArchiveOptions, pkiArchiveOptsBuf),
          ASN_Delete);
        ASNBuf_Del(pkiArchiveOptsBuf);
        if (pkiArchiveOpts.get() == NULL)
        {
          /*# Exception : �߸��� pkiArchiveOptions �� */
          /*# LOG : pkiArchiveOptions �ؼ� ���� */
          CMPSendErrorException e(
            LOG_CAMSGD_FAIL_TO_RESOLVE_PKIARCHIVEOPTS_N);
          e.addOpts(
            "�ش� certReqMsg�� index(0����) : %i, �ش� pkiArchivalOptions(DER Encoded) : %a",
            ctx.reqIndex,
            ctx.certReqMsg->certReq->controls->member[i]->value);
          throw e;
        }
        /*# NOTE : PKIArhicveOptions�� encryptedPrivKey�� ����ϴ� ���
         *         EncryptedValue�� EnvelopedData�� ����ϴ� 2������ ��츦 ����� �� ������,
         *         ���⿡���� EncryptedValue�� �̿��ϴ� ��츸 �����ϰ� ����.
         */
        if (pkiArchiveOpts->select != PKIArchiveOptions_encryptedPrivKey ||
          pkiArchiveOpts->choice.encryptedPrivKey->select != CRMFEncryptedKey_encryptedValue)
        {
          /*# Exception : �������� �ʴ� ����� pkiArchiveOptions */
          /*# LOG : �������� �ʴ� ����� pkiArhiveOptions */
          CMPSendErrorException e(
            LOG_CAMSGD_UNSUPPORTED_PKIARCHIVEOPTS_N);
          e.addOpts(
            "�ش� certReqMsg�� index(0����) : %i, �ش� pkiArchivalOptions(DER Encoded) : %a",
            ctx.reqIndex,
            ctx.certReqMsg->certReq->controls->member[i]->value);
          throw e;
        }

        int encryptedPriKeyLen =
          pkiArchiveOpts->choice.encryptedPrivKey->choice.encryptedValue->encValue->len;
        boost::scoped_array<unsigned char> encryptedPriKey(
          new unsigned char[encryptedPriKeyLen]);
        int ret;
        if (pkiArchiveOpts->choice.encryptedPrivKey->choice.encryptedValue->encSymmKey == NULL)
        {
          /* Secret Key �� ��ȣȭ �Ǿ� �ִ� ���(Penta specific, RFC���� ����Ǿ� ���� ����) */
          char secretValue[MAX_SECRETVAL_LEN];
          if (_senderAuthInfo->select != PKISenderAuthInfo_secretValue)
          {
            /*# Exception : �߸��� pkiArchiveOptions �� */
            /*# LOG : pkiArchiveOptions �ؼ� ���� */
            CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_RESOLVE_PKIARCHIVEOPTS_N);
            e.addOpts(
              "�ش� certReqMsg�� index(0����) : %i, �ش� pkiArchivalOptions(DER Encoded) : %a",
              ctx.reqIndex,
              ctx.certReqMsg->certReq->controls->member[i]->value);
            throw e;
          }
          VERIFY(::ASNOctStr_Get(
            secretValue, sizeof(secretValue),
            _senderAuthInfo->choice.secretValue->secretValue) != FAIL);
          ret = ::EncryptedValue_Get(
            pkiArchiveOpts->choice.encryptedPrivKey->choice.encryptedValue,
            NULL,
            encryptedPriKey.get(), &encryptedPriKeyLen, encryptedPriKeyLen,
            reinterpret_cast<unsigned char *>(secretValue),
            NULL, ::strlen(secretValue),
            NULL);
        }
        else
        {
          if (CALoginProfile::get())
          {
            /* CA ����Ű�� ��ȣȭ �Ǿ� �ִ� ��� */

            // CA�� ����Ű�� ���ŵ� ��쿡�� �� ����Ű�� ������ ����Ű �� ���
            // ������ ��ȣȭ �Ͽ� ���޵Ǿ������� �Ǵ��� ���� ���� ������,
            // �� ��쿡�� ������ ����Ű�� �����Ǵ� �����Ű�� ��ȣȭ�� �غ���.
            CnKSharedPtrs cnKs(AuthorityLoginProfile::get()->getMyCnKs());
            CnKSharedPtrs::iterator itr(cnKs.begin());
            PrivateKeyInfo *caPrivateKey = itr->second.get();
            ++itr;
            PrivateKeyInfo *oldCAPrivateKey =
              (itr != cnKs.end()) ? itr->second.get() : NULL;
            ret = ::EncryptedValue_Get(
              pkiArchiveOpts->choice.encryptedPrivKey->choice.encryptedValue,
              caPrivateKey,
              encryptedPriKey.get(), &encryptedPriKeyLen, encryptedPriKeyLen,
              NULL, NULL, 0, NULL);
            if (ret != SUCCESS)
            {
              ret = ::EncryptedValue_Get(
                pkiArchiveOpts->choice.encryptedPrivKey->choice.encryptedValue,
                oldCAPrivateKey,
                encryptedPriKey.get(), &encryptedPriKeyLen, encryptedPriKeyLen,
                NULL, NULL, 0, NULL);
            }
          }
          else
            continue;
        }
        if (ret != SUCCESS)
        {
          /*# Exception : ��ȣȭ ���� */
          /*# LOG : PKIArchiveOptions ���� �����Ű ��ȣȭ ���� */
          CMPSendErrorException e(
            LOG_CAMSGD_FAIL_TO_DECRYPT_PRIKEY_IN_ARCHIVEOPT_N);
          e.addOpts(
            "�ش� certReqMsg�� index(0����) : %i, �ش� pkiArchivalOptions(DER Encoded) : %a",
            ctx.reqIndex,
            ctx.certReqMsg->certReq->controls->member[i]->value);
          throw e;
        }

        ASNBuf priKeyBuf;
        ASNBuf_SetP(
          &priKeyBuf,
          reinterpret_cast<char *>(encryptedPriKey.get()), encryptedPriKeyLen);
        PrivateKeyInfo *priKey = ASN_New(PrivateKeyInfo, &priKeyBuf);
        if (priKey == NULL)
        {
          /*# Exception : ��ȣȭ ���� */
          /*# LOG : PKIArchiveOptions ���� �����Ű ��ȣȭ ���� */
          CMPSendErrorException e(
            LOG_CAMSGD_FAIL_TO_DECRYPT_PRIKEY_IN_ARCHIVEOPT_N);
          e.addOpts(
            "�ش� certReqMsg�� index(0����) : %i, �ش� pkiArchivalOptions(DER Encoded) : %a",
            ctx.reqIndex,
            ctx.certReqMsg->certReq->controls->member[i]->value);
          throw e;
        }

        VERIFY(::ASNSeq_NewSetPOptional(
          pASN(&ctx.reqCertInfo->privateKey), ASN_SEQ(ctx.reqCertInfo.get()),
          ASN(priKey)) == SUCCESS);
      }
    } /* for (i=0; i< certReqMsg->certReq->controls->size; i++) */
  }  /* if (certReqMsg->certReq->controls != NULL) */
}

void CMP::makeCerts()
{
  for (vector<ISSUE_CONTEXT>::iterator i = _issueCtx.begin();
    i != _issueCtx.end(); i++)
  {
    if (i->certResponse.get())
      continue;
    // ������ ��� �н��ϸ� _revocable�� false�̰�
    // ���� ���߿� �����ص� revoke�� �ʿ����.

    try
    {
      makeOneCert(*i);
      // �̰��� ������ ��μ� revocable�ϴ�.
      _revocable = true;
    }
    catch (CMPException &e)
    {
      // error response ����
      VERIFY(e.getErrorMsgContent());
      i->certResponse.reset(ASN_New(CertResponse, NULL), ASN_Delete);
      ASN_Copy(
        i->certResponse->certReqId, i->certReqMsg->certReq->certReqId);
      ASN_Copy(
        i->certResponse->status, e.getErrorMsgContent()->pKIStatusInfo);
    }
  }
}

static void SetEncryptedPrivateKey(
  PKIEntityPKC *pkc,
  DBPolicy *policy, PrivateKeyInfo *priKey)
{
  Certificate *certs[2] = { NULL, NULL };
  Parameter *domainParams[2] = { NULL, NULL };
  AlgDesc hashAlgs[2] = { SHA1, SHA1 };
  int certNum = 1;

  VERIFY(pkc && policy && priKey);

  // ca ������ ���� ����
  certs[0] = AuthorityLoginProfile::get()->getCACerts().begin()->get();

  // Ű ���� ����� �����Ǿ� ������ Ű ���� ��� ������ �о����
  PKIEntityPKC krPKC;
  if (!policy->krsid.empty() && policy->krsid != CA_SELF_AUTHORITY_SID)
  {
    std::ostringstream ost;
    ost <<
      "ESID='" << policy->krsid << "' AND STAT='" << PKIDB_PKC_STAT_GOOD << "' "
      "ORDER BY CDATE DESC";
    PKIDBSel *select = ::PKI_DB_SelectRow(
      PKIENTITYPKC, &krPKC, DBConnection::getConn(), NULL,
      ost.str().c_str(), NULL);
    if (select != NULL)
    {
      ::PKI_DB_SelectClose(select);

      ASNBuf asnBuf;
      ASNBuf_SetP(&asnBuf, krPKC.pkc.data, krPKC.pkc.len);
      certs[1] = ASN_New(Certificate, &asnBuf);
      if (certs[1] != NULL) ++certNum;
    }
  }

  // ContentInfo �� ����
  ContentInfo *contentInfo = ASN_New(ContentInfo, NULL);
  VERIFY(::ASNOid_SetByNid(contentInfo->contentType, NID_data) == SUCCESS);
  VERIFY(::ASNSeq_NewOptional(
    pASN(&contentInfo->content), ASN_SEQ(contentInfo)) == SUCCESS);
  VERIFY(::ASNAny_SetASN(contentInfo->content, ASN(priKey)) == SUCCESS);

  // EnvelopedData ����
  EnvelopedData *envPriKey;
  int ret = ::EnvelopedData_Gen(
    &envPriKey,
    contentInfo,
    AuthorityLoginProfile::get()->getDefaultSymmAlgNid(),
    certNum, certs, domainParams, hashAlgs);
  ASN_Del(contentInfo);
  if (certs[1] != NULL) ASN_Del(certs[1]);
  if (ret != SUCCESS) return;

  ASNBuf *envPriKeyBuf = ::ASN_EncodeDER(envPriKey);
  VERIFY(envPriKeyBuf != NULL);
  ASN_Del(envPriKey);

  // pkc�� setting
  ::memcpy(pkc->ekey.data, envPriKeyBuf->data, envPriKeyBuf->len);
  pkc->ekey.len = envPriKeyBuf->len;
  ASNBuf_Del(envPriKeyBuf);

  if (certNum == 2) pkc->krcert = krPKC.ser;
  else
  {
    char buf[4096];
    VERIFY(::ASNInt_GetStr(
      buf, sizeof(buf),
      certs[0]->tbsCertificate->serialNumber) != FAIL);
    pkc->krcert = buf;
  }
}

int CMP::getPCRL_UnitCerts()
{
  static int unit = atoi(LoginProfile::get()->
    getProfile("CRL", "UNIT_CERTS").c_str());
  return unit;
}

bool CMP::isPCRL()
{
  static bool mod = LoginProfile::get()->
    getProfile("CRL", "TYPE") == "partitioned";
  int unit = getPCRL_UnitCerts();
  return mod && unit;
}

std::string CMP::getPCRL_CdpUriFormat()
{
  static string uri = LoginProfile::get()->getProfile("CRL",
      "CDP_URI_FORMAT");
  return uri;
}

int CMP::getPCRL_CurrentCertsCount()
{
  string count = AuthorityLoginProfile::get()->getDP()->get(
      PKIDB_GLOBAL_CERT_SECTION, PKIDB_GLOBAL_CERT_COUNT);
  return atoi(count.c_str());
}

std::string CMP::getPCRL_CdpUri(int certCount)
{
  if (isPCRL())
  {
    string fmtUri = LoginProfile::get()->getProfile("CRL", "CDP_URI_FORMAT");

    if (!fmtUri.empty())
    {
      char uri[2048];
      sprintf(uri, fmtUri.c_str(), certCount / getPCRL_UnitCerts());
      return uri;
    }
  }
  return "";
}

void CMP::makeOneCert(ISSUE_CONTEXT &ctx)
{
  int ret;
  CnKSharedPtr caCnK(AuthorityLoginProfile::get()->getMyCnK());

  DBSubject *sender = dynamic_cast<DBSubject *>(_sender.get());
  // sender�� �ϳ���!
  DBSubject *certHolder = dynamic_cast<DBSubject *>(ctx.certHolder.get());
  DBPolicy *policy = boost::polymorphic_downcast<DBPolicy*>(ctx.policy.get());
  PKIReqCertInfo *reqCertInfo = ctx.reqCertInfo.get();
  int reqIdx = ctx.reqIndex;

  boost::shared_ptr<Certificate> newCert(
    ASN_New(Certificate, NULL), ASN_Delete);
  /*# FIXME : ���̻� PKIEntityInfo, PKIIssuerInfo, PKIPolicyInfo�� �� �ʿ䰡 �����Ƿ�
   *          �ٸ� ������� ������ �����ϴ� ���� ����� ��
   */
  PKIEntityInfo *entityInfo = ASN_New(PKIEntityInfo, NULL);
  PKIPolicyInfo *policyInfo = ASN_New(PKIPolicyInfo, NULL);
  PKIIssuerInfo *issuerInfo = ASN_New(PKIIssuerInfo, NULL);

  VERIFY(::PKIEntityInfo_SetByStr(
    entityInfo, certHolder->getDN().c_str(), NULL, 0) == SUCCESS);
  if (certHolder->getSubAltName() != NULL)
    VERIFY(::ASNSeq_NewSetOptional(
      pASN(&entityInfo->subAltName), ASN_SEQ(entityInfo),
      ASN(certHolder->getSubAltName())) == SUCCESS);
  DBEntity *entity = dynamic_cast<DBEntity*>(certHolder);
  if (entity != NULL && entity->vlimit != 0)
  {
    struct tm notAfter;
    VERIFY(::ASNSeq_NewOptional(
      pASN(&entityInfo->notAfter), ASN_SEQ(entityInfo)) == SUCCESS);
    notAfter = *gmtime(&entity->vlimit);
    Time_Set(entityInfo->notAfter, &notAfter);
  }

  ASNBuf extensionsBuf;
  ASNBuf_SetP(&extensionsBuf, policy->plcder.data, policy->plcder.len);
  Extensions *extensions = ASN_New(Extensions, &extensionsBuf);
  VERIFY(::PKIPolicyInfo_Set(
    policyInfo, extensions,
    policy->valdyear, policy->valdmon, policy->valdday,
    policy->valdhour) == SUCCESS);
  ASN_Del(extensions);
  /*# FIXME : memory copy �� ȿ�������� �Ͼ�� ������ �� */
  VERIFY(::PKIIssuerInfo_Set(
    issuerInfo, false, caCnK.first.get(), caCnK.second.get()) == SUCCESS);

  string cdpuri;
  int certscount = 0;
  if (dynamic_cast<DBEntity*>(certHolder) && isPCRL())
  {
    TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
    certscount = getPCRL_CurrentCertsCount();
    cdpuri = getPCRL_CdpUri(certscount);
    TRACE_LOG(TMPLOG, cdpuri.c_str());
  }
  TRACE_LOG(TMPLOG, "%d, %s", isPCRL(), PRETTY_TRACE_STRING);

  ret = CERT_MakeCertificate(
    newCert.get(),
    entityInfo, reqCertInfo,
    policyInfo, issuerInfo, cdpuri.c_str());
  ASN_Del(entityInfo);
  ASN_Del(policyInfo);
  ASN_Del(issuerInfo);
  if (ret != SUCCESS)
  {
    /*# ERROR : ������ ���� ���� */
    /*# LOG : ������ ���� ���� */
    CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_GEN_CERT_N);
    e.addOpts(
      "�ش� certReqMsg�� index(0����) : %i, ���� �ڵ� : %i",
      reqIdx, ret);
    throw e;
  }

  // ������ ����
  if ((entity = dynamic_cast<DBEntity*>(certHolder)) != NULL)
  {
    DBEntityPKC *entityPKC = new DBEntityPKC(newCert.get());
    entityPKC->esid = certHolder->getSID();
    entityPKC->csid = sender->getSID();
    // conf ���� ���ο� ���� GOOD/REVOKE ����
    entityPKC->stat = PKIDB_PKC_STAT_HOLD;
    entityPKC->psid = policy->sid;
    // partitioned crl
    if (!cdpuri.empty())
      entityPKC->cdp = cdpuri;

    if (reqCertInfo->privateKey != NULL)
      SetEncryptedPrivateKey(entityPKC, policy, reqCertInfo->privateKey);

    // FIXME - Ű ���� ����� ���� ó��!
    // ekey;            /**< ��ȣȭ�� �����Ű(Not implemented) */
    // krcert[100];     /**< �����Ű ��ȣȭ�� ���� Ű������� �������� �Ϸù�ȣ */
    try
    {
      entityPKC->insert();

      if (!cdpuri.empty())
      {
        // cdp ���� ���� ������ ���� ī��Ʈ 1 ����
        char newcount[300];
        sprintf(newcount, "%d", certscount + 1);
        AuthorityLoginProfile::get()->getDP()->set(PKIDB_GLOBAL_CERT_SECTION,
            PKIDB_GLOBAL_CERT_COUNT, newcount);
      }
    }
    catch (DBCommandException)
    {
      delete entityPKC;
      /*# ERROR : �߱޵� �������� DB�� �����ϴµ� ����(systemFailure(draft)) */
      /*# LOG : ������ �������� DB�� �����ϴµ� ���� */
      CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_INSERT_CERT_TO_DB_N);
      e.addOpt("�ش� certReqMsg�� index(0����)", reqIdx);
      throw e;
    }
    ctx.pkc.reset(entityPKC);
  }
  else
  {
    DBAuthorityPKC *authorityPKC =
      new DBAuthorityPKC(newCert.get());
    authorityPKC->asid = certHolder->getSID();
    authorityPKC->stat = PKIDB_PKC_STAT_HOLD;
    try
    {
      authorityPKC->insert();
    }
    catch (DBCommandException)
    {
      delete authorityPKC;
      /*# ERROR : �߱޵� �������� DB�� �����ϴµ� ����(systemFailure(draft)) */
      /*# LOG : ������ �������� DB�� �����ϴµ� ���� */
      CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_INSERT_CERT_TO_DB_N);
      e.addOpt("�ش� certReqMsg�� index(0����)", reqIdx);
      throw e;
    }
    ctx.pkc.reset(authorityPKC);
  }
}

void CMP::makeCertResponse()
{
  // POP�� encCert ����� ��쿡�� ���� �޽��� ���� �������� ������� ����Ű�� �̿��Ͽ�
  // hybrid������� ��ȣȭ �Ͽ� ������ ��, ����ڷκ����� conf �޽����� �������� ��ȣȭ �ϴµ�
  // ����� ���Ű�� �̿��Ͽ� �����Ͽ��� �Ѵ�.
  // ����, ������ ���Ű�� ������ ��ȣȭ(�������� �� ���� ����)�� conf �޽��� ������ ���ǹǷ�
  for (vector<ISSUE_CONTEXT>::iterator i = _issueCtx.begin();
    i != _issueCtx.end(); i++)
  {
    if (i->certResponse.get())
      continue;
    // response�� �̹� �����Ǿ� �ִ� ���(���� response)���� certResponse�� �������� ����

    try
    {
      makeOneCertResponse(*i);
    }
    catch (CMPException &e)
    {
      // error response ����
      VERIFY(e.getErrorMsgContent());
      CertResponse *errorResponse = ASN_New(CertResponse, NULL);
      ASN_Copy(
        errorResponse->certReqId, i->certReqMsg->certReq->certReqId);
      ASN_Copy(
        errorResponse->status, e.getErrorMsgContent()->pKIStatusInfo);
      i->certResponse.reset(errorResponse, ASN_Delete);
    }
  }
}

void CMP::makeOneCertResponse(ISSUE_CONTEXT &ctx)
{
  int ret;
  DBPKC *newPKC = dynamic_cast<DBPKC *>(ctx.pkc.get());

  CertResponse *certResponse = ASN_New(CertResponse, NULL);
  ASN_Copy(certResponse->certReqId, ctx.certReqMsg->certReq->certReqId);

  /*# FIXME: PKIStatus_grantedWithMods�� ó���ϱ� */
  VERIFY(::ASNInt_SetInt(
    certResponse->status->status, PKIStatus_accepted) == SUCCESS);
  /*# NOTE: ���� ���������� CA���� Ű�� �������� �����Ƿ� privateKey ������ ������� ���� */
  VERIFY(::ASNSeq_NewOptional(
    pASN(&certResponse->certifiedKeyPair), ASN_SEQ(certResponse)) == SUCCESS);

  int popTech;
  VERIFY(::ASNInt_GetInt(&popTech, ctx.reqCertInfo->popTechnique) == SUCCESS);
  if (popTech != POP_Technique_EKPOPEncryptedCert)
  {
    VERIFY(::ASNChoice_Select(
      ASN_CHOICE(certResponse->certifiedKeyPair->certOrEncCert),
      CertOrEncCert_certificate) == SUCCESS);
    ASN_Copy(
      certResponse->certifiedKeyPair->certOrEncCert->choice.certificate,
      newPKC->getCertificate().get());
  }
  else
  {
    // POP�� EncCert�� �Ǵ� ���
    VERIFY(::ASNChoice_Select(
      ASN_CHOICE(certResponse->certifiedKeyPair->certOrEncCert),
      CertOrEncCert_encryptedCert) == SUCCESS);
    ASNBuf encodedCertBuf;
    RandAnsiContext randCtx;

    if (_encCertSymmKey.get() == NULL)
    {
      // ���� Ű�� �����Ǿ� ���� ���� ��� ���Ű�� ����
      _encCertSymmKey.reset(
        ::ASNBuf_New(DEFAULT_SYMMETRIC_KEY_LEN), ASNBuf_Delete);

      ::RANDANSI_Initialize(&randCtx);
      ::RANDANSI_GetRandomNum(
        reinterpret_cast<unsigned char*>(
          _encCertSymmKey->data),
        DEFAULT_SYMMETRIC_KEY_LEN, &randCtx);
      _encCertSymmKey->len = DEFAULT_SYMMETRIC_KEY_LEN;
    }

    DBEntityPKC *entityPKC;
    DBAuthorityPKC *authorityPKC;

    if ((entityPKC = dynamic_cast<DBEntityPKC*>(newPKC)) != NULL)
    {
      ASNBuf_SetP(&encodedCertBuf, entityPKC->pkc.data, entityPKC->pkc.len);
    }
    else
    {
      authorityPKC =
        boost::polymorphic_downcast<DBAuthorityPKC *>(newPKC);
      ASNBuf_SetP(
        &encodedCertBuf, authorityPKC->pkc.data, authorityPKC->pkc.len);
    }

    AlgorithmIdentifier *symmAlg = ASN_New(AlgorithmIdentifier, NULL);
    AlgorithmIdentifier *hashAlg = ASN_New(AlgorithmIdentifier, NULL);
    VERIFY(::AlgorithmIdentifier_SetNid(
      symmAlg, AuthorityLoginProfile::get()->getDefaultSymmAlgNid(), NULL) == SUCCESS);
    VERIFY(::AlgorithmIdentifier_SetNid(hashAlg, NID_SHA1, NULL) == SUCCESS);
    ret = ::EncryptedValue_Set(
      certResponse->certifiedKeyPair->certOrEncCert->choice.encryptedCert,
      (unsigned char*)encodedCertBuf.data,
      encodedCertBuf.len,
      reinterpret_cast<unsigned char*>(_encCertSymmKey->data),
      _encCertSymmKey->len,
      symmAlg,
      newPKC->getCertificate()->tbsCertificate->subjectPublicKeyInfo,
      hashAlg);
    ASN_Del(symmAlg);
    ASN_Del(hashAlg);
    if (ret != SUCCESS)
    {
      /*# ERROR: Fail to make encrypted value (systemFailure(draft)) */
      /*# LOG : ������ �������� ��ȣȭ �ϴµ� ���� */
      CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_ENCRYPT_CERT_N);
      e.addOpts(
        "�ش� certReqMsg�� index(0����) : %i, "
        "����Ű �˰����� OID : %o",
        ctx.reqIndex,
        &newPKC->getCertificate()->tbsCertificate->subjectPublicKeyInfo->algorithm->algorithm->oid);
      throw e;
    }
  }
  ctx.certResponse.reset(certResponse, ASN_Delete);
}

}
