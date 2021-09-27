/**
 * @file    CMP_getSender.cpp
 *
 * @desc    ��û�ڿ� ���� ������ �������� function
 * @author  ������(hrcho@pentasecurity.com)
 * @since   2002.05.10
 *
 * Revision history
 *
 * @date    2002.05.10 : Start
 */

// standard headers
#include <sstream>

// cis headers
#include "x509com.h"
#include "pkiinfo.h"

// pkilib headers
#include "Trace.h"
#include "DBSubject.hpp"
#include "DBObject.hpp"
#include "DBPKC.hpp"
#include "DBAuthority.hpp"
#include "CMPSocket.hpp"

// pkimsgd headers
#include "AuthorityLoginProfile.hpp"
#include "CMP.hpp"
#include "CMPException.hpp"
#include "PKILogTableDefine.hpp"

using namespace std;
using namespace Issac::DB;

namespace Issac
{

//////////////////////////////////////////////////////////////////////
// CMPGetSenderInfoCommand Class
//////////////////////////////////////////////////////////////////////
void CMP::getSender() // set _senderAuthInfo, _sender and _senderAuth
{
  // DB���� �������� �����ʹ� ��û�ڿ� ���� �������̸�,
  // ����� ������ 3������ ���еȴ�.
  // 1. �޽����� �������� ��ȣ�Ǿ� �ִ� ���
  //    DB�κ��� header�� sender���� �̿��Ͽ� ��û�� ������ ���� ������ �����´�.
  // 2. �޽����� MAC���� ��ȣ�Ǿ� �ְ�, header�� sender���� null�� ���(ir, ccr, genm �޽����� ��쿡 ����)
  //    ir,ccr �޽����� ��쿡�� DB�κ��� header�� senderKID ���� �̿��Ͽ� ��û�� ������ ���� ������
  //    ��û ��� ���� ������ �����´�.
  //    genm �޽����� ��쿡�� DB�κ��� header�� senderKID ���� �̿��Ͽ� ��û�� ������ ���� ������ �����´�.
  // 3. �޽����� MAC���� ��ȣ�Ǿ� �ְ�, header�� sender���� null�� �ƴ� ���(rr�޽����� ��쿡 ����)
  //    DB�κ��� header�� sender���� �̿��Ͽ� ��û�� ������ ���� ������ ������ ���� ��û ó���� ���� ������ �����´�.

  // 0. sender fields�� �ùٸ��� Ȯ��
  if (_reqMessage->header->sender->select != GeneralName_directoryName)
  {
    /*# ERROR: Error Message ����(badDataFormat : �߸��� header) */
    /*# LOG : sender�� directoryName�� �ƴ�  */
    CMPSendErrorException e(LOG_CAMSGD_INVALID_SENDER_TYPE_N);
    e.addOpt("sender�� chioce ��",
        _reqMessage->header->sender->select - 1);
    throw e;
  }
  if (AlgNid_CheckSigAlg(_reqMessage->header->protectionAlg->algorithm->nid))
  {
    // 1. �������� ��ȣ�Ǿ� �ִ� ���
    // 1.1. �޽����κ��� ��û�� �̸�(sender name)�� ����
    char senderDN[512];
    if (::Name_SprintLine(
      senderDN, sizeof(senderDN), _reqMessage->header->sender->choice.directoryName) < 0)
    {
      /*# ERROR: Error Message ����(badDataFormat : �߸��� header) */
      /*# LOG : sender�� �ؼ� ����  */
      CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_RESOLVE_SENDER_N);
      e.addOpt(
        "sender ��(DER Encoded)",
        reinterpret_cast<ASN *>(_reqMessage->header->sender));
      throw e;
    }
    // 1.2. ��û���� ���� �� ������ ��������
    std::ostringstream ost;
    ost << "DN='" << senderDN << "'";

    DBObjectSharedPtr senderCert;
    DBObjectSharedPtr sender;
    try
    {
      sender = DBEntity::select(ost.str().c_str());
    }
    catch (DBException)
    {
      try
      {
        sender = DBAuthority::select(ost.str().c_str());
      }
      catch (DBException)
      {
        /*# ERROR : Error Message ����(signerNotTrusted(draft) : sender�� ã�� �� ����) */
        /*# LOG : sender���� �̿��Ͽ� ��û�� ������ ã�µ� ����  */
        CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_FIND_SENDER_INFO_N);
        e.addOpt("��û�� DN", senderDN);
        throw e;
      }
    }
    _sender = sender;
    try
    {
      senderCert =
        dynamic_cast<Issac::DB::DBSubject *>(sender.get())->
          getDefaultCert(_reqMessage->header->senderKID);
    }
    catch (Exception)
    {
      /*# ERROR : Error Message ����(signerNotTrusted(draft) : ������ �����ϱ� ���� sender ������ �������� ����) */
      /*# LOG : sender ������ ���� ����  */
      CMPSendErrorException e(LOG_CAMSGD_SENDER_NOT_TRUSTED_N);
      e.addOpt("��û�� DN", senderDN);
      throw e;
    }

    PKISenderAuthInfo *senderAuthInfo = ASN_New(PKISenderAuthInfo, NULL);
    try
    {
      ::PKISenderAuthInfo_SetCertAndPriKey(
        senderAuthInfo,
        dynamic_cast<Issac::DB::DBPKC *>(senderCert.get())->getCertificate().get(),
        NULL, NULL, 0);
    }
    catch (Exception)
    {
      ASN_Del(senderAuthInfo);
      /*# ERROR : Error Message ����(signerNotTrusted(draft) :
          ������ �����ϱ� ���� sender ������ �������� ����) */
      /*# LOG : sender ������ ���� ����  */
      CMPSendErrorException e(LOG_CAMSGD_SENDER_NOT_TRUSTED_N);
      e.addOpt("��û�� DN", senderDN);
      throw e;
    }
    _senderAuthInfo.reset(senderAuthInfo, ASN_Delete);

    // 1.3. ��û���� ������ ����(Not implemented)
    /*# NOTE : ���ʷ� �߱��ϴ� ���� ��ȣ ���� CA ��ü�� �������� �����ϴ� �͵� ���� �ʿ䰡 ������ ������ �� */
  }
  else if (_reqMessage->header->protectionAlg->algorithm->nid
    == NID_passwordBasedMac)
  {
    if (_reqMessage.get()->header->sender->choice.directoryName->
      choice.rdnSequence->size == 0)
    {
      // 2. �޽����� MAC���� ��ȣ�Ǿ� �ְ�, header�� sender���� null��
      //    ���(reference number ����� ���)
      //    (ir, ccr, genm �޽����� ��쿡 ����)
      if (_reqMessage.get()->body->select != PKIBody_ir &&
        _reqMessage.get()->body->select != PKIBody_ccr &&
        _reqMessage.get()->body->select != PKIBody_genm)
      {
        /*# ERROR: Error Message ����(wrongIntegrity : �߸��� ��û) */
        /*# LOG : �߸��� protection ���(Reference number ���)  */
        CMPSendErrorException e(LOG_CAMSGD_WRONG_INTEGRITY_REFNUM_N);
        e.addOpt("PKIBody�� choice ��",
            _reqMessage.get()->body->select - 1);
        throw e;
      }
      if (_reqMessage.get()->header->senderKID == NULL)
      {
        /*# ERROR : Error Message ����(badRequest : �߸��� header) */
        /*# LOG : senderKID ���� �������� ���� */
        CMPSendErrorException e(LOG_CAMSGD_MISSING_SENDERKID_N);
        throw e;
      }
      char refnum[128];
      VERIFY(FAIL != ::ASNOctStr_Get(
        refnum, sizeof(refnum), _reqMessage->header->senderKID));

      std::ostringstream ost;
      ost << "REFNUM='" << refnum << "'";

      DBObjectSharedPtr sender;
      DBObjectSharedPtr senderAuth;

      try
      {
        senderAuth = DBEntityAuth::select(ost.str().c_str());
      }
      catch (DBException)
      {
        try
        {
          senderAuth = DBAuthorityAuth::select(ost.str().c_str());
        }
        catch (DBException)
        {
          /*# ERROR : Error Message ����(signerNotTrusted(draft) : ���� �˻� ����) */
          /*# LOG : �־��� reference number�� �ش��ϴ� ������ ã�µ� ���� */
          CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_FIND_REFNUM_N);
          e.addOpt("Reference number", refnum);
          throw e;
        }
      }

      time_t timeNow = ::time(NULL);
      time_t timeSDate =
        dynamic_cast<Issac::DB::DBAuth *>(senderAuth.get())->getRefSDate();
      time_t timeEDate =
        dynamic_cast<Issac::DB::DBAuth *>(senderAuth.get())->getRefEDate();
      if (timeSDate != 0 && timeSDate > timeNow ||
        timeEDate != 0 && timeEDate < timeNow)
      {
        /*# ERROR : Error Message ����(signerNotTrusted(draft) : refnum ���Ⱓ ����ġ */
        /*# LOG : Reference number�� ��ȿ���� ���� */
        CMPSendErrorException e(LOG_CAMSGD_REFNUM_NOT_AVAILABLE_N);
        e.addOpts(
          "Reference number : %s, Reference number ��ȿ�Ⱓ : %t���� %t����",
          refnum, timeSDate, timeEDate);
        throw e;
      }

      try
      {
        sender = dynamic_cast<Issac::DB::DBAuth *>(senderAuth.get())->getSubject();
      }
      catch (DBSelectException)
      {
        /*# ERROR : Error Message ����(systemFailure(draft) : DB integrity ����) */
        /*# LOG : PKIEntityAuth(PKIAuthorityAuth) ���̺��� SID�� �ش� ��û�� ������ ã�µ� ���� */
        CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_FIND_SENDER_BY_SID_N);
        e.addOpts(
          "Reference number : %s, ��û�� SID : %s",
          refnum,
          dynamic_cast<Issac::DB::DBAuth *>(senderAuth.get())->getSID().c_str());
        throw e;
      }
      _sender = sender;
      PKISenderAuthInfo *senderAuthInfo = ASN_New(PKISenderAuthInfo, NULL);
      ::PKISenderAuthInfo_SetSecretValue(
          senderAuthInfo,
          dynamic_cast<DBAuth *>(senderAuth.get())->getRefNum().c_str(),
          dynamic_cast<DBAuth *>(senderAuth.get())->getRefVal().c_str(),
          0, 0, 0);
      _senderAuthInfo.reset(senderAuthInfo, ASN_Delete);
      _senderAuth = senderAuth;

      _removeRefnum = true;      // �����Ŀ� reference number�� ����
    }
    else
    {
      // 3. �޽����� MAC���� ��ȣ�Ǿ� �ְ�, header�� sender���� null�� �ƴ� ���(rr�޽����� ��쿡 ����)
      if (_reqMessage.get()->body->select != PKIBody_rr)
      {
        /*# ERROR: Error Message ����(badRequest : �߸��� ��û) */
        /*# LOG : �߸��� protection ���(RevPassPhrase ���)  */
        CMPSendErrorException e(LOG_CAMSGD_WRONG_INTEGRITY_REVPASS_N);
        e.addOpt("PKIBody�� choice ��", _reqMessage.get()->body->select-1);
        throw e;
      }
      // 3.1. �޽����κ��� ��û�� �̸�(sender name)�� ����
      char senderDN[512];
      if (::Name_SprintLine(
        senderDN, sizeof(senderDN),
        _reqMessage->header->sender->choice.directoryName) < 0)
      {
        /*# ERROR: Error Message ����(badDataFormat : �߸��� header) */
        /*# LOG : sender�� �ؼ� ����  */
        CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_RESOLVE_SENDER_N);
        e.addOpt(
          "sender ��(DER Encoded)",
          reinterpret_cast<ASN *>(_reqMessage->header->sender));
        throw e;
      }
      // 3.2. ��û���� ���� �� ������ ��������
      std::ostringstream ost;
      ost << "DN='" << senderDN << "'";

      DBObjectSharedPtr sender;
      try
      {
        sender = DBEntity::select(ost.str().c_str());
      }
      catch (DBException)
      {
        // 1.2.1. PKIEntity ���̺� ������ ���� ���
        // CA�� revPassPhrase�� ���� ������ ���Ȼ� �������� ����
        /*# ERROR : Error Message ����(signerNotTrusted(draft) : sender�� ã�� �� ����) */
        /*# LOG : sender���� �̿��Ͽ� ��û�� ������ ã�µ� ����  */
        CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_FIND_SENDER_INFO_N);
        e.addOpt("��û�� DN", senderDN);
        throw e;
      }

      if (static_cast<DBEntity *>(sender.get())->revpass.empty())
      {
        /*# ERROR : Error Message ����(signerNotTrusted(draft) : revPassPhrase�� ��ϵǾ� ���� ����) */
        /*# LOG : revPassPhrase�� ��ϵǾ� ���� ���� */
        CMPSendErrorException e(LOG_CAMSGD_REVPASS_NOT_REGISTERED_N);
        e.addOpt("��û�� DN", senderDN);
        throw e;
      }
      _sender = sender;
      PKISenderAuthInfo *senderAuthInfo = ASN_New(PKISenderAuthInfo, NULL);
      ::PKISenderAuthInfo_SetRevPassPhrase(
          _senderAuthInfo.get(),
          _reqMessage->header->sender->choice.directoryName,
          static_cast<DBEntity *>(sender.get())->revpass.c_str(),
          0, 0);
      _senderAuthInfo.reset(senderAuthInfo, ASN_Delete);
    }
  }
  else
  {
    /*# ERROR: Error Message ����(�˼����� protectionAlg: badAlg) */
    /*# LOG : �� �� ���� ����� protection ��� */
    CMPSendErrorException e(LOG_CAMSGD_UNKNOWN_PROTECTIONALG_N);
    e.addOpt(
      "��û �޽����� header ��(DER Encoded)",
      reinterpret_cast<ASN *>(_reqMessage.get()->header));
    throw e;
  }
}

}
