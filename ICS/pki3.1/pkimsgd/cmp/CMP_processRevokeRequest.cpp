/**
 * @file    CMP_processRevokeRequest_CA.cpp
 *
 * @desc    폐지 신청 메시지(rr)을 처리하는 function
 * @author  조현래(hrcho@pentasecurity.com)
 * @since   2002.05.07
 *
 * Revision History
 *
 * @date    2002.05.07 : Start
 *
 *
 */

// standard headers
#include <sstream>
#include <cassert>
#include <boost/cast.hpp>

// cis headers
#include "cmp_types.h"

// pkilib headers
#include "Trace.h"
#include "DBSubject.hpp"
#include "DBPKC.hpp"
#include "DBPolicy.hpp"
#include "CMPSocket.hpp"
#include "Log.hpp"
#include "CnK_define.hpp"

// pkimsgd headers
#include "CALoginProfile.hpp"
#include "CMP.hpp"
#include "CMPException.hpp"
#include "CMPHelper.hpp"
#include "PKILogTableDefine.hpp"

#ifdef __CYGWIN__
#define TRACEFILE "/cygdrive/c/camsgd.log"
#else
#define TRACEFILE "/tmp/camsgd.log"
#endif

using namespace std;
using namespace Issac::DB;

namespace Issac
{

/**
 * 인증서 폐지 신청 메시지 처리 과정은 다음과 같다.
 *
 * 1. CA의 경우
 *  1) DB로부터 폐지할 인증서의 정보를 가져옴
 *  2) 해당 인증서가 존재하고 또한 상태가 'Good'인지 확인
 *  3) DB로부터 해당 인증서 소유자의 정보를 가져옴
 *  4) 요청자가 해당 인증서의 폐지를 요청할 권한이 있는지 확인
 *  5) 인증서의 상태를 'REVOKE'로 변경
 *  6) 응답 메시지 생성
 * 2. RA의 경우
 *  1) DB로부터 폐지할 인증서의 정보를 가져옴
 *  2) 해당 인증서가 존재하고 또한 상태가 'Good'인지 확인
 *  3) DB로부터 해당 인증서 소유자의 정보를 가져옴
 *  4) 요청자가 해당 인증서의 폐지를 요청할 권한이 있는지 확인
 *  5) 1)~4)의 과정에서 검증된 요청에 대해서 CA에게 인증서 폐지를 요청
 *    - CA에게 보낼 요청 메시지는 RA가 수신한 요청 메시지와 동일한 값들을 사용
 *    - CA에게 요청 메시지 전달
 *    - CA로부터 응답 메시지 수신
 *  6) CA의 응답 메시지 중에 성공한 요청에 대해 DB내의 인증서의 상태를 'REVOKE'로 변경
 *  7) 응답 메시지 생성
 */
// CMPRevRequestCommand::CMPRevRequestCommand()
void CMP::processRevokeRequest()
{
  TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
  initRevokeContext();
  TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
  resolveRevDetails();
  TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
  checkSenderCanRevoke();
  TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
  if (CALoginProfile::get())
  {
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    revokeCerts();
  }
  else
  {
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    requestRevokeToCA();
  }
  TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
  makeRevokeResContest();

}

void CMP::initRevokeContext()
{
  // 1. 폐지 신청을 처리하기 위한 초기화 과정 수행
  RevReqContent *revReqContent = _reqMessage->body->choice.rr;

  if (revReqContent->size == 0)
    /*# ERROR: Error Message 전송(badDataFormat : 잘못된 Body) */
    /*# LOG : 인증서 폐지 요청 메시지의 Body가 비어있음 */
    throw CMPSendErrorException(LOG_CAMSGD_EMPTY_REVREQUEST_BODY_N);

  // 2. 응답 메시지 body 등록
  _resBody.reset(ASN_New(PKIBody, NULL), ASN_Delete);
  ASNChoice_Select(ASN_CHOICE(_resBody.get()), PKIBody_rp);

  // Memory 처리의 효율성을 높이기 위해 PKIMessage내의
  // RevReqContent를 복사하지 않고 약간의 꽁수(?)를 사용.
  // 일반적으로는 ASN_Dup등을 사용하여 element를 복사한 뒤,
  // 새로 생성된 element를 context item으로 setting해야 하나
  // (복사를 하지 않으면 현 context의 구현상 2번 free하게 됨)
  // 여기에서는 PKIMessage내의 RevReqContent의 size를 0으로 setting하여
  // PKIMessage로부터 context로 pointer의 소유권을 직접 이동시키는 방법을 사용하였다.
  int reqCount = revReqContent->size; // stores original size
  revReqContent->size = 0;         // discards ownership of pointers

  int reqIdx;
  for (reqIdx = 0 ; reqIdx < reqCount ;reqIdx++)
  {
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    REVOKE_CONTEXT ctx;
    _revokeCtx.push_back(ctx);

    _revokeCtx[reqIdx].reqIndex = reqIdx;
    _revokeCtx[reqIdx].revDetails.reset(revReqContent->member[reqIdx],
      ASN_Delete);
  }
  TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
}

void CMP::resolveRevDetails()
{
  for (vector<REVOKE_CONTEXT>::iterator i = _revokeCtx.begin();
    i != _revokeCtx.end(); i++)
  {
    try
    {
      if (i->revDetails->certDetails->serialNumber == NULL)
      {
        /*# ERROR: Serialnumber가 지정되지 않음 */
        /*# LOG : 폐지 요청 메시지에 폐지할 인증서의 일련 번호가 포함되어 있지 않음 */
        CMPSendErrorException e(LOG_CAMSGD_MISSING_SERIALNUMBER_TO_REVOKE_N);
        e.addOpt("해당 RevDetails의 index(0부터)", i->reqIndex);
        throw e;
      }

      // 폐지할 인증서 정보를 가져옴
      std::ostringstream ost;
      DBObjectSharedPtr pkc;

      ost <<
        "SER='" <<
        type2string<ASNInt *>(i->revDetails->certDetails->serialNumber) << '\'';
      try
      {
        TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
        pkc = DBEntityPKC::select(ost.str().c_str());
      }
      catch (DBException)
      {
        TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
        try
        {
          pkc = DBAuthorityPKC::select(ost.str().c_str());
        }
        catch (DBException)
        {
          /*# ERROR: 해당 인증서를 찾을 수 없음 */
          /*# LOG : 폐지할 인증서를 찾을 수 없음 */
          std::ostringstream ost;
          ost <<
              type2string<ASNInt *>(i->revDetails->certDetails->serialNumber);
          CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_FIND_CERT_TO_REVOKE_N);
          e.addOpt("폐지 요청이 된 인증서의 일련 번호", ost.str());
          throw e;
        }
      }

      if (dynamic_cast<DBPKC*>(pkc.get())->getStat() ==
        PKIDB_PKC_STAT_REVOKED)
      {
        /*# ERROR: 이미 폐지된 인증서 */
        /*# LOG : 이미 폐지가 된 인증서에 대한 폐지 요청 */
        std::ostringstream ost;
        ost << type2string<ASNInt *>(i->revDetails->certDetails->serialNumber);
        CMPSendErrorException e(LOG_CAMSGD_CERT_ALREADY_REVOKED_N);
        e.addOpt("폐지 요청이 된 인증서의 일련 번호", ost.str());
        throw e;
      }

      i->pkc = pkc;
      // 폐지할 인증서의 소유자에 대한 정보를 가져옴
      // FIXME : 동일한 사용자에 대하여 폐지를 요청하는 경우가 빈번하게
      //         있을 수가 있으니
      //         한번 가져온 사용자에 대해서는 CACHE등의 방법을 사용하여
      //         효율성을 높일 것
      DBObjectSharedPtr certHolder;
      DBEntityPKC *entityPKC;
      DBAuthorityPKC *authorityPKC;

      if ((entityPKC = dynamic_cast<DBEntityPKC*>(pkc.get())) != NULL)
      {
        if ((dynamic_cast<DBSubject*>(_sender.get())->getType()) ==
          PKIDB_ENTITY_TYPE_RA)
        {
          // RA 사용자들
          if (dynamic_cast<DBSubject*>(_sender.get())->getSID() != entityPKC->csid)
          {
            /*# ERROR : RA는 자신에게 속한 사용자에게 대해서만 폐지를 요청할 수 있음 */
            /*# LOG : 등록기관은 자신에게 속한 사용자들의 인증서에 대해서만 폐지를 요청할 수 있음 */
            std::ostringstream ost;
            ost <<
                type2string<ASNInt *>(i->revDetails->certDetails->serialNumber);
            CMPSendErrorException e(LOG_CAMSGD_RA_NOT_AUTHORIZED_REVOKE_N);
            e.addOpt("폐지 요청이 된 인증서의 일련 번호", ost.str());
            throw e;
          }
          certHolder = DBObjectSharedPtr(
            new DBRAEntity(
              dynamic_cast<DBEntity*>(_sender.get()),
              entityPKC->dn));
        }
        else
        {
          ost.str("");
          ost << "SID='" << entityPKC->esid << "'";
          try
          {
            certHolder = DBEntity::select(ost.str().c_str());
          }
          catch (DBException)
          {
            /*# ERROR : DB integrity */
            /*# LOG : 해당 인증서의 주체에 대한 정보를 DB에서 찾는데 실패 */
            std::ostringstream ost;
            ost <<
                type2string<ASNInt *>(i->revDetails->certDetails->serialNumber);
            CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_FIND_REVOKED_SUBJECT_BY_SID_N);
            e.addOpt("폐지 요청이 된 인증서의 일련 번호", ost.str());
            throw e;
          }
        }
      }
      else
      {
        authorityPKC =
          boost::polymorphic_downcast<DBAuthorityPKC*>(pkc.get());
        ost.str("");
        ost << "SID='" << authorityPKC->asid << "'";
        try
        {
          certHolder = DBAuthority::select(ost.str().c_str());
        }
        catch (DBException)
        {
          /*# ERROR : DB integrity */
          /*# LOG : 해당 인증서의 주체에 대한 정보를 DB에서 찾는데 실패 */
          std::ostringstream ost;
          ost <<
              type2string<ASNInt *>(i->revDetails->certDetails->serialNumber);
          CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_FIND_REVOKED_SUBJECT_BY_SID_N);
          e.addOpt("폐지 요청이 된 인증서의 일련 번호", ost.str());
          throw e;
        }
      }
      i->certHolder = certHolder;
    }
    catch (CMPException &e)
    {
      // Log 기록
      LogItemSharedPtr logItem(AuthorityLoginProfile::get()->getLog()->createLogItem());
      logItem->setLogItem(e.getCode(), e.getOpts().c_str());
      logItem->setRequester(getLogReqInfo(_sender, _sock.getPeerName()));
      //logItem->setWorker(DBObjectBase::getSelf());
      logItem->write();
      // Error response 설정
      i->revStatus.reset(reinterpret_cast<PKIStatusInfo *>(
          ASN_Dup(ASN(e.getErrorMsgContent()->pKIStatusInfo))),
        ASN_Delete);
      continue;
    }
  }
}

void CMP::checkSenderCanRevoke()
{
  DBSubject *sender = dynamic_cast<DBSubject *>(_sender.get());
  DBSubject *certHolder;

  TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
  for (vector<REVOKE_CONTEXT>::iterator i = _revokeCtx.begin();
    i != _revokeCtx.end(); i++)
  {
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    if (i->revStatus.get())
        continue;
        // response가 이미 생성되어 있는 경우(error)

    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    try
    {
      TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
      // 1. 요청 대상에 대한 요청자의 권한 검사
      certHolder = dynamic_cast<DBSubject *>(i->certHolder.get());

      TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
      try
      {
        TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
        checkSenderPrivilege(sender, certHolder);
      }
      catch (CMPSendErrorException &e)
      {
        TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
        /*# Exception : 권한 검사 실패 */
        std::ostringstream ost;
        ost <<
              type2string<ASNInt *>(i->revDetails->certDetails->serialNumber);
        e.addOpt("폐지 요청이 된 인증서의 일련 번호", ost.str());
        throw e;
      }
      TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);

      // 1.1. RA 사용자인 경우, 동일한 RA로부터의 폐지 요청인지 확인
      if (dynamic_cast<DBRAEntity*>(certHolder) != NULL)
      {
        TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
        DBEntityPKC *pkc = dynamic_cast<DBEntityPKC*>(i->pkc.get());
        DBEntity *ra = dynamic_cast<DBEntity*>(_sender.get());

        if (pkc->csid != ra->sid)
        {
          TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
          /*# ERROR : RA는 자신에게 속한 사용자에게 대해서만 폐지를 요청할 수 있음 */
          /*# LOG : 등록기관은 자신에게 속한 사용자들의 인증서에 대해서만 폐지를 요청할 수 있음 */

          std::ostringstream ost;
          ost <<
              type2string<ASNInt *>(i->revDetails->certDetails->serialNumber);
          CMPSendErrorException e(LOG_CAMSGD_RA_NOT_AUTHORIZED_REVOKE_N);
          e.addOpt("폐지 요청이 된 인증서의 일련 번호", ost.str());
          throw e;
        }
        TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
      }

      TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
      // 2. 요청 대상의 권한 검사( 현 CA의 경우에는 폐지 요청 불가능 )
      DBAuthority *authority;
      if ((authority = dynamic_cast<DBAuthority*>(certHolder)) != NULL)
      {
        TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
        if (authority->type == PKIDB_AUTHORITY_TYPE_SELF)
        {
          TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
          /*# ERROR : 현 CA의 인증서에 대해서는 폐지 요청 불허 */
          /*# LOG : 현 CA의 인증서 폐지 요청 */
          std::ostringstream ost;
          ost <<
              type2string<ASNInt *>(i->revDetails->certDetails->serialNumber);
          CMPSendErrorException e(
            LOG_CAMSGD_REVOKE_REQUEST_FOR_THIS_CA_CERT_N);
          e.addOpt("폐지 요청이 된 인증서의 일련 번호", ost.str());
          throw e;
        }
        TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
      }
      TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    }
    catch (CMPException& e)
    {
      TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
      // Log 기록
      LogItemSharedPtr logItem(AuthorityLoginProfile::get()->getLog()->createLogItem());
      logItem->setLogItem(e.getCode(), e.getOpts().c_str());
      logItem->setRequester(getLogReqInfo(_sender, _sock.getPeerName()));
      //logItem->setWorker(DBObjectBase::getSelf());
      logItem->write();
      // Error response 설정
      i->revStatus.reset(reinterpret_cast<PKIStatusInfo *>(
          ASN_Dup(ASN(e.getErrorMsgContent()->pKIStatusInfo))),
        ASN_Delete);
      continue;
    }
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
  }
}

// ca only
void CMP::revokeCerts()
{
  TRACE_LOG(TRACEFILE, "-------------------void CMP::revokeCerts()");
  for (vector<REVOKE_CONTEXT>::iterator i = _revokeCtx.begin();
    i != _revokeCtx.end(); i++)
  {
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    if (i->revStatus.get())
      continue;

    boost::shared_ptr<PentaRevDescription> revDesc;

    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    if (i->revDetails->crlEntryDetails != NULL)
    {
      // pentaRevDescription 처리
      revDesc.reset(
        Extensions_GetByType(
          NULL, i->revDetails->crlEntryDetails,
          PentaRevDescription, NID_pentaRevDescription),
        ASN_Delete);
    }

    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    try
    {
      TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
      dynamic_cast<DBPKC *>(i->pkc.get())->revoke(
        _sender,
        ReasonFlagsToReasonCode(i->revDetails->revocationReason),
        (revDesc.get() == NULL)
          ? "" : type2string<ASNUTF8Str *>(revDesc.get()).c_str() );
    }
    catch (DBException)
    {
      TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
      /*# ERROR : 인증서 폐지 실패(DB내 인증서 상태 갱신 실패) */
      /*# LOG : 인증서 폐지 실패(DB내 인증서 상태 갱신 실패) */
      // error response 설정(not implemented)
      CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_REVOKE_CERT_IN_DB_N);
      e.addOpt("폐지 요청이 된 인증서의 일련 번호",
        dynamic_cast<DBPKC*>(i->pkc.get())->getSerialNumber());
      throw e;
    }

    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    // PKIStatusInfo 설정
    PKIStatusInfo *statusInfo = ASN_New(PKIStatusInfo, NULL);
    VERIFY(::ASNInt_SetInt(statusInfo->status, PKIStatus_accepted) == SUCCESS);
    i->revStatus.reset(statusInfo, ASN_Delete);

    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    /*# LOG : 인증서 폐지 과정 완료 */

    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    DBEntityPKC *entityPKC =
      dynamic_cast<DBEntityPKC*>(i->pkc.get());
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    DBAuthorityPKC *authorityPKC =
      dynamic_cast<DBAuthorityPKC*>(i->pkc.get());
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    DBAuthority *authority =
      dynamic_cast<DBAuthority*>(i->certHolder.get());

    VERIFY(entityPKC || authority);
    std::ostringstream ost;

    ost <<
      "SID='" <<
      ((entityPKC != NULL) ? entityPKC->psid : authority->psid) <<
      '\'';
    DBObjectSharedPtr policy(DBPolicy::select(ost.str().c_str()));

    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    LogItemSharedPtr logItem(AuthorityLoginProfile::get()->getLog()->createLogItem());
    logItem->setLogItem(
      LOG_CAMSGD_CERTIFICATE_REVOKED_N,
      "폐지된 인증서 일련 번호 : %s, 인증서 정책 명 : %s, 추가 폐지 정보 : %s",
      dynamic_cast<DBPKC*>(i->pkc.get())->getSerialNumber().c_str(),
      dynamic_cast<DBPolicy*>(policy.get())->name.c_str(),
      ((entityPKC != NULL) ? entityPKC->rdesc : authorityPKC->rdesc).c_str());
    //logItem->setWorker(DBObjectBase::getSelf());
    logItem->setRequester(getLogReqInfo(_sender, _sock.getPeerName()));
    logItem->setCertHolder(getLogHolderInfo(i->certHolder));
    logItem->write();
  }
}

void CMP::makeRevokeResContest()
{
  TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
  RevRepContent *revResContent = _resBody->choice.rp;
  VERIFY(::ASNSeq_NewOptional(
    pASN(&revResContent->revCerts), ASN_SEQ(revResContent)) == SUCCESS);

  for (vector<REVOKE_CONTEXT>::iterator i = _revokeCtx.begin();
    i != _revokeCtx.end(); i++)
  {
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    CertId *certId = ASN_New(CertId, NULL);
    ::GenName_Set(
      certId->issuer, GeneralName_directoryName,
      AuthorityLoginProfile::get()->getCACerts().begin()->get()->tbsCertificate->subject);
    int status;
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    VERIFY(::ASNInt_GetInt(&status, i->revStatus->status) == SUCCESS);
    if (i->revDetails->certDetails->serialNumber != NULL)
      ASN_Copy(certId->serialNumber, i->revDetails->certDetails->serialNumber);
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);

    VERIFY(::ASNSeqOf_Add(
      ASN_SEQOF(revResContent->status), ASN(i->revStatus.get())) == SUCCESS);
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    VERIFY(::ASNSeqOf_AddP(
      ASN_SEQOF(revResContent->revCerts), ASN(certId)) == SUCCESS);
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
  }
  TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
}

}
