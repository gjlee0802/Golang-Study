/**
 * @file    CMP_processCertRequest.cpp
 *
 * @desc    ������ ��û �޽���(ir, cr, kur, ccr)�� ó���ϴ� function
 * @author   ������(hrcho@pentasecurity.com)
 * @since    2002.05.01
 *
 * Revision History
 *
 * @date     2002.05.01 : Start
 *
 *
 */

// standard headers
#include <sstream>
#include <boost/cast.hpp>

// cis headers
#include "pkiinfo.h"

// pkisys headers
#include "dbi.h"

#include "Trace.h"

// pkilib headers
#include "DBSubject.hpp"
#include "cis_cast.hpp"
#include "CMPSocket.hpp"

#include "CMP.hpp"
#include "CMPException.hpp"
#include "PKILogTableDefine.hpp"

using namespace Issac::DB;
using namespace std;

#define TMPLOG "/tmp/cmp.log"

namespace Issac
{

void CMP::processCertRequest()
{
  _certRequest = true;
  getCertHolder();
  checkSenderCanIssue();
  issueCerts();
}

void CMP::getCertHolder() // set _certHolder
{
  CertReqMessages *certReqMessages = _reqMessage->body->choice.ir;

  if (certReqMessages->size < 1)
    /*# ERROR: Error Message ����(badDataFormat : �߸��� Body) */
    /*# LOG: ������ �߱� ��û �޽����� Body�� ������� */
    throw CMPSendErrorException(LOG_CAMSGD_EMPTY_ISSUEREQUEST_BODY_N);

  /**
   * ��û ��� ���� ������ PKIEntity/PKIAuthority table�� �����Ϳ�
   * ��û ��� ���� �Ҵ�Ǿ� �ִ� PKIPolicy table�� �����͸� �������� ���еȴ�.
   * ��û ��� ���� ������ �������� ������ ������ 3������ ���еȴ�.
   *
   * 1. ��û�� protection�� reference number�� secret value���� ������ MAC protection�� ���
   *  - ��û ����� ��û�ڿ� �����ϹǷ� ��û�� �����κ��� ��û ��� ���� ������ �����Ѵ�.
   * 2. ��û�� ��û���� ������ �̿��� protection�̰�, ��û�ڶ� ��û ����� ���� ���
   *  - ��û�� �����κ��� ��û ��� ���� ������ �����Ѵ�.
   * 3. ��û�� ��û���� ������ �̿��� protection�̰�, ��û�ڶ� ��û ����� �ٸ� ���
   *  - ������ ��û �޽��� ���� DN ���� �̿��Ͽ� ��û ��� ���� ������ DB�� ���� �����´�.
   *    ��, ��û�ڰ� RA�� ��쿡�� DB���� ��û ��� ���� ������ �������� �����Ƿ�,
   *    ��û���� RA�� ������ ������ ��û �޽��� ���� ������ �̿��Ͽ� ��û ��� ���� ������ �����Ѵ�.
   */
  switch (_senderAuthInfo->select)
  {
  case PKISenderAuthInfo_secretValue :
  {
    // ��û�ڿ� ��û ����� ����
    _certHolder = _sender;
    // ������ ��û �޽��� ���� DN���� �ùٸ��� Ȯ��
    for (int reqIdx = 0; reqIdx < certReqMessages->size; ++reqIdx)
    {
      if (certReqMessages->member[reqIdx]->certReq->certTemplate->subject != NULL )
      {
        char certHolderDN[512];
        if (::Name_SprintLine(
          certHolderDN, sizeof(certHolderDN),
          certReqMessages->member[reqIdx]->certReq->certTemplate->subject)
          == SUCCESS)
        {
          if (::strcmp(
            dynamic_cast<DBSubject*>(_sender.get())->getDN().c_str(),
            certHolderDN) != 0)
          {
            /*# ERROR : Error Message ����(notAuthorized : ����ڴ� �ٸ� ������� ������ �߱��� ��û�� �� ����) */
            /*# LOG : ����ڴ� �ٸ� ������� ������ �߱��� ��û�� �� ���� */
            CMPSendErrorException e(LOG_CAMSGD_REQUESTED_BY_USER_N);
            e.addOpt("�߱� ��� DN", certHolderDN);
            throw e;
          }
        } // �ùٸ� ������ Name�� �ƴ� ���(����)
      }
    }
    break;
  }
  case PKISenderAuthInfo_certAndPriKey :
  {
    Name *certHolderDNName =
      certReqMessages->member[0]->certReq->certTemplate->subject;
    if (certHolderDNName == NULL)
    {
      /*# ERROR: Error Message ����(badDataFormat : certTemplate�� subject���� �����ؾ� ��) */
      /*# LOG : ������ �߱� ��û �޽��� ���� certTemplate�� subject ���� �������� ���� */
      CMPSendErrorException e(LOG_CAMSGD_MISSING_SUBJECT_IN_CERTTEMPLATE_N);
      e.addOpt("PKIBody�� choice ��", _reqMessage.get()->body->select-1);
      throw e;
    }
    // CertReqMessages ���� ��� ��û�� ������ �߱� ��� ���� ������ ��û���� Ȯ��
    for (int reqIdx = 1; reqIdx < certReqMessages->size; ++reqIdx)
    {
      if (certReqMessages->member[reqIdx]->certReq->certTemplate->subject !=
        NULL)
      {
        if (::Name_Compare(
          certHolderDNName,
          certReqMessages->member[reqIdx]->certReq->certTemplate->subject) != SUCCESS)
        {
          /*# ERROR: Error Message ����(badRequest : certTemplate�� subject���� ��� ���ƾ� ��) */
          /*# LOG : ������ �߱� ��û �޽��� ���� certTemplate�� subject ������ ���� �������� ���� */
          CMPSendErrorException e(LOG_CAMSGD_MULTIPLE_SUBJECT_N);
          e.addOpts(
            "�߱� ��� DN(1) : %s, �߱� ��� DN(2) : %s",
            type2string<Name*>(certHolderDNName).c_str(),
            type2string<Name*>(
              certReqMessages->member[reqIdx]->certReq->certTemplate->subject).c_str());
          throw e;
        }
      } // else : 2��° request���ʹ� subject ���� ����
    }

    char certHolderDN[512];
    ::Name_SprintLine(certHolderDN, sizeof(certHolderDN), certHolderDNName);
    if (dynamic_cast<DBSubject*>(_sender.get())->getDN() ==
      certHolderDN)
    {
      // ��û�ڿ� ��û ����� ����
      _certHolder = _sender;
    }
    else
    {
      // ��û�ڿ� ��û ����� �ٸ�
      DBEntity *entity = dynamic_cast<DBEntity *>(_sender.get());
      if (entity == NULL)
      {
        /*# ERROR: Error Message ����(notAuthorized : CA�� �ٸ� ������� ������ �߱��� ��û�� �� ����) */
        /*# LOG : Ÿ CA�� �ٸ� ������� ������ �߱��� ��û�� �� ���� */
        CMPSendErrorException e(LOG_CAMSGD_REQUESTED_BY_OTHERCA_N);
        e.addOpt("�߱� ��� DN", certHolderDN);
        throw e;
      }

      if (entity->type != PKIDB_ENTITY_TYPE_RA)
      {
        // ��û ����� �� �������� ������� ���

        // ��û���� ���� ��������
        std::ostringstream ost;
        ost << "DN='" << certHolderDN << "'";

        DBObjectSharedPtr certHolder;
        try
        {
          certHolder =  DBEntity::select(ost.str().c_str());
        }
        catch (DBException)
        {
          try
          {
            certHolder = DBAuthority::select(ost.str().c_str());
          }
          catch (DBException)
          {
            /*# ERROR : Error Message ����(badRequest: ��û ����� ã�� �� ����) */
            /*# LOG : �߱� ��� ���� ������ ã�µ� ���� */
            CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_FIND_SUBJECT_INFO_N);
            e.addOpt("�߱� ��� DN", certHolderDN);
            throw e;
          }
        }
        _certHolder = certHolder;
      }
      else
      {
        // ��û ����� RA �������� ������� ���
        DBObjectSharedPtr certHolder(
          new DBRAEntity(entity, certHolderDN, certReqMessages));
        _certHolder = certHolder;
      }
    }
    break;
  }
  default:
    VERIFY(false);
  }
}

void CMP::checkSenderCanIssue()
{
  TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
  // 1. ��û���� ���� �˻�
  checkSenderPrivilege(dynamic_cast<DBSubject*>(_sender.get()),
    dynamic_cast<DBSubject*>(_certHolder.get()));

  // 2. �߱� ����� ���� �˻�
  DBAuthority *authority;
  DBEntity *entity;
  Issac::DB::DBRAEntity *ra;

  if ((authority = dynamic_cast<DBAuthority*>(_certHolder.get()) ) != NULL)
  {
    // ��ȣ ��������� ��� �߱��� �㰡�Ǿ� �ִ��� �˻�
    if (authority->type == PKIDB_AUTHORITY_TYPE_CROSS)
    {
      if (authority->crstype != PKIDB_CROSSCERT_BY_CERT &&
        authority->crstype != PKIDB_CROSSCERT_BY_CERT_N_CTL)
        /*# ERROR: Error Message ����(badRequest : �߱��� �㰡���� ����) */
        /*# LOG : ������ �߱��� �㰡���� ���� ��ȣ ���� ���(CTL ���) */
        throw CMPSendErrorException(LOG_CAMSGD_SUBJECT_NOT_AUTHORIZED_N);
    }
    else if (authority->type != PKIDB_AUTHORITY_TYPE_SUB)
      /*# ERROR: Error Message ����(badRequest : �߱��� �㰡���� ����) */
      /*# LOG : �� CA�� ������ �߱� ��û */
      throw CMPSendErrorException(LOG_CAMSGD_REQUEST_FOR_THIS_CA_CERT_N);
  }
  else if ((ra = dynamic_cast<Issac::DB::DBRAEntity*>(_certHolder.get())) != NULL)
  {
    // RA DBEntity�� ���
    // ��û�� ������� DN���� ���� ����ڵ��� DN���� ��ġ���� �˻�
    std::ostringstream ost;
    ost <<
      "SELECT COUNT(*) FROM PKIENTITY "
      "WHERE DN='" << ra->dn << '\'';
    PKIDBSel *sel = ::DBI_Select(
      DBConnection::getConn(), ost.str().c_str());
    if (sel != NULL)
    {
      if (::DBI_ResultGetIntByCol(0, sel) > 0)
      {
        ::DBI_ResultFree(sel);
        /*# ERROR: ������ DN���� ���� ����ڰ� ���� */
        /*# LOG : ������ DN ���� ���� ���� ����ڰ� ���� */
        CMPSendErrorException e(LOG_CAMSGD_DUPLICATE_DN_N);
        e.addOpt("�߱� ��� DN", ra->dn);
        throw e;
      }
      else ::DBI_ResultFree(sel);
    }

    // �ش� ��û ��󿡰� ������ �߱޵� �������� �ִ� ���, ������ RA�κ��� �߱޵� ������ Ȯ��
    ost.str("");
    ost <<
      "SELECT COUNT(*) FROM PKIENTITYPKC "
      "WHERE DN = '" << ra->dn << "'"
      "      AND CSID!='" << dynamic_cast<DBSubject*>(_sender.get())->getSID() << '\'';
    sel = ::DBI_Select(
      DBConnection::getConn(), ost.str().c_str());
    if (sel != NULL)
    {
      if (::DBI_ResultGetIntByCol(0, sel) > 0)
      {
        ::DBI_ResultFree(sel);
        /*# ERROR: ������ DN���� ���� ����ڰ� ���� */
        /*# LOG : ������ DN ���� ���� ���� ����ڰ� ���� */
        CMPSendErrorException e(LOG_CAMSGD_DUPLICATE_DN_N);
        e.addOpt("�߱� ��� DN", ra->dn);
        throw e;
      }
      else ::DBI_ResultFree(sel);
    }
  }
  else
  {
    entity = boost::polymorphic_downcast<DBEntity *>(_certHolder.get());
    // �߱� ��ȿ�Ⱓ �˻�
    if (entity->vlimit != 0 && entity->vlimit < ::time(NULL))
    {
      /*# ERROR: Error Message ����(badRequest : �߱� ����� ��ȿ�Ⱓ ���� */
      /*# LOG : �߱� ����� ��ȿ�Ⱓ ���� */
      CMPSendErrorException e(LOG_CAMSGD_SUBJECT_VLIMIT_EXPIRED_N);
      e.addOpts("�߱� ����� ��ȿ�Ⱓ : %t����", entity->vlimit);
      throw e;
    }
  }

  // 3. ��Ÿ ���� �˻�
  //   - ccr�� �߱� ����� ��ȣ ���� CA �� ��쿡 ���Ͽ� ��û ����
  if (_reqMessage->body->select == PKIBody_ccr)
  {
    if (dynamic_cast<DBAuthority *>(_certHolder.get()) == NULL)
    {
      /*# ERROR: Error Message ����(badRequest : �߱��� �㰡���� ����) */
      /*# LOG : ccr �޽����� ��ȣ �����ÿ��� ���� */
      CMPSendErrorException e(LOG_CAMSGD_CCR_USED_FOR_NON_AUTHORITY_N);
      e.addOpt("�߱� ��� DN",
        dynamic_cast<DBEntity*>(_certHolder.get())->dn);
      throw e;
    }
  }
}

}
