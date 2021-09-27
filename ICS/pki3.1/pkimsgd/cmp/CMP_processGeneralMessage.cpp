/**
 * @file    CMP_processGeneralMessage.cpp
 *
 * @desc    General message(genp)를 처리하는 function
 * @author  조현래(hrcho@pentasecurity.com)
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
  // 1. General message를 처리하기 위한 초기화 과정 수행
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

  // Memory 처리의 효율성을 높이기 위해 PKIMessage내의
  // GenMsgContent를 복사하지 않고 약간의 꽁수(?)를 사용.
  // 일반적으로는 ASN_Dup등을 사용하여 element를 복사한 뒤,
  // 새로 생성된 element를 context item으로 setting해야 하나
  // (복사를 하지 않으면 현 context의 구현상 2번 free하게 됨)
  // 여기에서는 PKIMessage내의 GenMsgContent의 size를 0으로 setting하여
  // PKIMessage로부터 context로 pointer의 소유권을 직접 이동시키는 방법을 사용하였다.
  int reqCount = genMsgContent->size; // stores original size
  genMsgContent->size = 0;         // discards ownship of pointers

  TRACE_LOG(TMPLOG, "member size: %d\n%s", reqCount, PRETTY_TRACE_STRING);
  int reqIndex;
  for (reqIndex = 0 ; reqIndex < reqCount ; ++reqIndex)
  {
    InfoTypeAndValue *infoReq = genMsgContent->member[reqIndex];
    InfoTypeAndValue *infoRes;
    /* message type 추출 및 분기 */
    switch (infoReq->infoType->nid)
    {
    case NID_penta_at_cmp_keyPolicyReq:
      TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
      infoRes = getKeyPolicy(infoReq);
      if (infoRes == NULL) // 생성 샐패
        continue; // FIXME : General Message에서의 에러 처리 생각해 보기
      break;
    case 0:   // CIS에 등록되어 있지 않은 oid
    default:  // 처리 하지 않는 oid
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
  // 1. KeyPolicyRequest 값 생성
  KeyPolicyRequest *keyPolicyRequest;

  if (ASNAny_GetASN(pASN(&keyPolicyRequest),
    infoReq->infoValue, KeyPolicyRequest) != SUCCESS)
  {
    /*# ERROR : 잘못된 형식의 KeyPolicyRequest */
    return NULL;
  }
  TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
  // exception 등의 경우에 자동으로 해제되도록 shared_ptr로 관리
  boost::shared_ptr<KeyPolicyRequest> request(
    keyPolicyRequest, ASN_Delete);

  // 2. 정책 정보를 가져올 대상에 대한 정보를 가져옴
  DBObjectSharedPtr entity;
  TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);

  char sender[512];
  if (keyPolicyRequest->requesterId != NULL)
  {
    TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
    // reference number 를 이용
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
        /*# ERROR : 해당 entity를 찾을 수 없음 */
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
      /*# ERROR : DB integrity 문제 */
      return NULL;
    }
  }
  else if (keyPolicyRequest->requesterName != NULL)
  {
    TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
    // DN을 이용
    if (::Name_SprintLine(
      sender, sizeof(sender), keyPolicyRequest->requesterName) < 0)
    {
      TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
      /*# ERROR : 잘못된 형식의 DN */
      return NULL;
    }

    // 1.2. 신청자의 정보 및 인증서 가져오기
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
        /*# ERROR : 해당 entity를 찾을 수 없음 */
        return NULL;
      }
    }
  }
  else
  {
    TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
    /*# ERROR : 잘못된 형식의 KeyPolicyRequest */
    return NULL;
  }
  TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);

  // 2. 정책 정보를 가져와서 결과값을 생성
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
      /*# ERROR : RA가 아닌 대상에 대해 RA 정책을 요청 */
      return NULL;
    }

    DBRAEntity *raEntity;
    try
    {
      TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);
      // RA 정책을 가져오기 위한 dummy entity 생성
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
        // 더이상의 policy가 없음
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
        /*# ERROR : 잘못된 DBPolicy 값 */
        delete raEntity;
        return NULL;
      }

      if (index != 0) ost << ", ";
      ost << "'" << dynamic_cast<DBPolicy*>(policy.get())->sid << "'";
      index++;
    }
    delete raEntity;
    TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING);

    // RA에 할당되어 있지 않은 정책들도 가져옴
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
        /*# ERROR : 잘못된 DBPolicy 값 */
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
        // 더이상의 policy가 없음
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
        /*# ERROR : 잘못된 DBPolicy 값 */
        return NULL;
      }
    }
  }

  /* 응답 InfoTypeAndValue 생성 */
  InfoTypeAndValue *infoRes = ASN_New(InfoTypeAndValue, NULL);
  VERIFY(::ASNOid_SetByNid(
    infoRes->infoType, NID_penta_at_cmp_keyPolicyRes) == SUCCESS);
  infoRes->infoValue = ASN_New(ASNAny, NULL);
  VERIFY(::ASNAny_SetASN(
    infoRes->infoValue, ASN(keyPolicies.get())) == SUCCESS);

  return infoRes;
}

}
