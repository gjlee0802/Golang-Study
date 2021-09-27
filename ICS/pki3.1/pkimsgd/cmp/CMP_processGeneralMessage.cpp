/**
 * @file    CMP_processGeneralMessage.cpp
 *
 * @desc    General message(genp)�� ó���ϴ� function
 * @author  ������(hrcho@pentasecurity.com)
 * @since   2002.05.14
 *
 * Revision History
 *
 * @date     2002.05.14 : Start
 *
 *
 */

// standard headers
#include <sstream>
#include <cassert>
#include <boost/shared_ptr.hpp>
#include <boost/scoped_array.hpp>

// cis headers
#include "pkimessage.h"

// pki headers
#include "DBAuthority.hpp"
#include "DBSubject.hpp"
#include "DBPolicy.hpp"
#include "Socket.hpp"

// pkimsgd headers
#include "CMP.hpp"
#include "CMPException.hpp"
#include "CMPHelper.hpp"

#include "Trace.h"

using namespace std;
using namespace Issac::DB;

#define TMPLOG "/tmp/cmp.log"

namespace Issac
{

void CMP::processGeneralMsg()
{
  // 1. General message�� ó���ϱ� ���� �ʱ�ȭ ���� ����
  GenMsgContent *genMsgContent = _reqMessage->body->choice.genm;

  TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);

  if (genMsgContent->size == 0)
  {
    TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
    /**
     * RFC2510bis-04 page 43
     *
     *  If sent from EE to CA, the empty set indicates that the CA may send
     *  any/all information that it wishes.
     */

    VERIFY(::ASNChoice_Select(ASN_CHOICE(_resBody.get()), PKIBody_genp) == SUCCESS);
    return;
  }

  _resBody.reset(ASN_New(PKIBody, NULL), ASN_Delete);

  TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
  VERIFY(::ASNChoice_Select(ASN_CHOICE(_resBody.get()), PKIBody_genp) == SUCCESS);
  TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);

  TRACE_LOG(TMPLOG, "%d\n%s", genMsgContent->member[0]->infoType->nid, PRETTY_TRACE_STRING);

  // Memory ó���� ȿ������ ���̱� ���� PKIMessage����
  // GenMsgContent�� �������� �ʰ� �ణ�� �Ǽ�(?)�� ���.
  // �Ϲ������δ� ASN_Dup���� ����Ͽ� element�� ������ ��,
  // ���� ������ element�� context item���� setting�ؾ� �ϳ�
  // (���縦 ���� ������ �� context�� ������ 2�� free�ϰ� ��)
  // ���⿡���� PKIMessage���� GenMsgContent�� size�� 0���� setting�Ͽ�
  // PKIMessage�κ��� context�� pointer�� �������� ���� �̵���Ű�� ����� ����Ͽ���.
  int reqCount = genMsgContent->size; // stores original size
  genMsgContent->size = 0;         // discards ownship of pointers

  TRACE_LOG(TMPLOG, "member size: %d\n%s", reqCount, PRETTY_TRACE_STRING);
  int reqIndex;
  for (reqIndex = 0 ; reqIndex < reqCount ; ++reqIndex)
  {
    InfoTypeAndValue *infoReq = genMsgContent->member[reqIndex];
    InfoTypeAndValue *infoRes;
    /* message type ���� �� �б� */
    switch (infoReq->infoType->nid)
    {
    case NID_penta_at_cmp_keyPolicyReq:
      TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
      infoRes = getKeyPolicy(infoReq);
      if (infoRes == NULL) // ���� ����
        continue; // FIXME : General Message������ ���� ó�� ������ ����
      break;
    case 0:   // CIS�� ��ϵǾ� ���� ���� oid
    default:  // ó�� ���� �ʴ� oid
      TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
      /**
       * RFC 2510 page 43
       *  The receiver is free to ignore any contained OBJ. IDs
       *  that it does not recognize.
       */
      continue;
    }
    TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
    VERIFY(::ASNSeqOf_AddP(
      ASN_SEQOF(_resBody->choice.genp), ASN(infoRes)) == SUCCESS);
  }
  TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
}

InfoTypeAndValue *CMP::getKeyPolicy(InfoTypeAndValue *infoReq)
{
  TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
  // 1. KeyPolicyRequest �� ����
  KeyPolicyRequest *keyPolicyRequest;

  if (ASNAny_GetASN(pASN(&keyPolicyRequest),
    infoReq->infoValue, KeyPolicyRequest) != SUCCESS)
  {
    /*# ERROR : �߸��� ������ KeyPolicyRequest */
    return NULL;
  }
  TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
  // exception ���� ��쿡 �ڵ����� �����ǵ��� shared_ptr�� ����
  boost::shared_ptr<KeyPolicyRequest> request(
    keyPolicyRequest, ASN_Delete);

  // 2. ��å ������ ������ ��� ���� ������ ������
  DBObjectSharedPtr entity;
  TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);

  char sender[512];
  if (keyPolicyRequest->requesterId != NULL)
  {
    TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
    // reference number �� �̿�
    char id[128];
    VERIFY(ASNOctStr_Get(
      id, sizeof(id), keyPolicyRequest->requesterId) != FAIL);

    std::ostringstream ost;
    ost << "REFNUM='" << id << "'";

    DBObjectSharedPtr entityAuth;
    try
    {
      entityAuth = DBEntityAuth::select(ost.str().c_str());
    }
    catch (DBException)
    {
      TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
      try
      {
        entityAuth = DBAuthorityAuth::select(ost.str().c_str());
      }
      catch (DBException)
      {
        TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
        /*# ERROR : �ش� entity�� ã�� �� ���� */
        return NULL;
      }
    }
    try
    {
      entity =
        dynamic_cast<DBAuth*>(entityAuth.get())->getSubject();
    }
    catch (DBSelectException)
    {
      TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
      /*# ERROR : DB integrity ���� */
      return NULL;
    }
  }
  else if (keyPolicyRequest->requesterName != NULL)
  {
    TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
    // DN�� �̿�
    if (::Name_SprintLine(
      sender, sizeof(sender), keyPolicyRequest->requesterName) < 0)
    {
      TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
      /*# ERROR : �߸��� ������ DN */
      return NULL;
    }

    // 1.2. ��û���� ���� �� ������ ��������
    std::ostringstream ost;
    ost << "DN='" << sender << "'";
    try
    {
      TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
      entity = DBEntity::select(ost.str().c_str());
    }
    catch (DBException)
    {
      TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
      try
      {
        entity = DBAuthority::select(ost.str().c_str());
      }
      catch (DBException)
      {
        TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
        /*# ERROR : �ش� entity�� ã�� �� ���� */
        return NULL;
      }
    }
  }
  else
  {
    TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
    /*# ERROR : �߸��� ������ KeyPolicyRequest */
    return NULL;
  }
  TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);

  // 2. ��å ������ �����ͼ� ������� ����
  boost::shared_ptr<KeyPolicies> keyPolicies(
    ASN_New(KeyPolicies, NULL), ASN_Delete);
  ASN_Copy(keyPolicies->transacId, keyPolicyRequest->transacId);

  DBSubject *subject =
    dynamic_cast<DBSubject*>(entity.get());

  if (keyPolicyRequest->rAPolicy)
  {
    TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
    if (subject->getType() != PKIDB_ENTITY_TYPE_RA)
    {
      TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
      /*# ERROR : RA�� �ƴ� ��� ���� RA ��å�� ��û */
      return NULL;
    }

    DBRAEntity *raEntity;
    try
    {
      TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
      // RA ��å�� �������� ���� dummy entity ����
      raEntity =
        new DBRAEntity(dynamic_cast<DBEntity*>(subject), sender, NULL);
      TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
    }
    catch (exception &e)
    {
      TRACE_LOG(TMPLOG, "%s", e.what());
    }

    TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
    std::ostringstream ost;
    int index = 0;
    while (true)
    {
      DBObjectSharedPtr policy;
      try
      {
        policy = raEntity->getPolicy(index);
      }
      catch (DBException)
      {
        TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
        // ���̻��� policy�� ����
        break;
      }
      try
      {
        TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
        VERIFY(::ASNSeqOf_AddP(
          ASN_SEQOF(keyPolicies->policies),
          ASN(PKIPolicyToKeyPolicy(
            static_cast<PKIPolicy *>(
              dynamic_cast<DBPolicy *>(policy.get())),
            true))) == SUCCESS);
      }
      catch (Exception)
      {
        TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
        /*# ERROR : �߸��� DBPolicy �� */
        delete raEntity;
        return NULL;
      }

      if (index != 0) ost << ", ";
      ost << "'" << dynamic_cast<DBPolicy*>(policy.get())->sid << "'";
      index++;
    }
    delete raEntity;
    TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);

    // RA�� �Ҵ�Ǿ� ���� ���� ��å�鵵 ������
    DBObjectVector otherPolicies;
    if (index > 0)
    {
      std::string strWhere;
      strWhere = "SID NOT IN (";
      strWhere += ost.str();
      strWhere += ")";

      otherPolicies = DBPolicy::selectObjects(strWhere.c_str());
    }
    else
    {
      otherPolicies = DBPolicy::selectObjects(NULL);
    }

    DBObjectVector::iterator itrPolicy;
    for (itrPolicy = otherPolicies.begin();
      itrPolicy != otherPolicies.end();
      ++itrPolicy)
    {
      try
      {
        VERIFY(::ASNSeqOf_AddP(
          ASN_SEQOF(keyPolicies->policies),
          ASN(PKIPolicyToKeyPolicy(
            static_cast<PKIPolicy *>(dynamic_cast<DBPolicy *>(
              itrPolicy->get()))))) == SUCCESS);
      }
      catch (Exception)
      {
        /*# ERROR : �߸��� DBPolicy �� */
        return NULL;
      }
    }
  }
  else
  {
    int index = 0;
    DBObjectSharedPtr policy;
    while (true)
    {
      try
      {
        policy = subject->getPolicy(index++);
      }
      catch (DBException)
      {
        // ���̻��� policy�� ����
        break;
      }
      try
      {
        VERIFY(::ASNSeqOf_AddP(
          ASN_SEQOF(keyPolicies->policies),
          ASN(PKIPolicyToKeyPolicy(
            static_cast<PKIPolicy *>(dynamic_cast<DBPolicy *>(
              policy.get()))))) == SUCCESS);
      }
      catch (Exception)
      {
        /*# ERROR : �߸��� DBPolicy �� */
        return NULL;
      }
    }
  }

  /* ���� InfoTypeAndValue ���� */
  InfoTypeAndValue *infoRes = ASN_New(InfoTypeAndValue, NULL);
  VERIFY(::ASNOid_SetByNid(
    infoRes->infoType, NID_penta_at_cmp_keyPolicyRes) == SUCCESS);
  infoRes->infoValue = ASN_New(ASNAny, NULL);
  VERIFY(::ASNAny_SetASN(
    infoRes->infoValue, ASN(keyPolicies.get())) == SUCCESS);

  return infoRes;
}

}
