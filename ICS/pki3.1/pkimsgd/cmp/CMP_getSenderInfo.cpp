/**
 * @file    CMP_getSender.cpp
 *
 * @desc    요청자에 대한 정보를 가져오는 function
 * @author  조현래(hrcho@pentasecurity.com)
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
  // DB에서 가져오는 데이터는 신청자에 대한 데이터이며,
  // 방법은 다음의 3가지로 구분된다.
  // 1. 메시지가 서명으로 보호되어 있는 경우
  //    DB로부터 header의 sender값을 이용하여 신청자 인증을 위한 정보를 가져온다.
  // 2. 메시지가 MAC으로 보호되어 있고, header의 sender값이 null인 경우(ir, ccr, genm 메시지인 경우에 한함)
  //    ir,ccr 메시지인 경우에는 DB로부터 header의 senderKID 값을 이용하여 신청자 인증을 위한 정보와
  //    신청 대상에 대한 정보를 가져온다.
  //    genm 메시지인 경우에는 DB로부터 header의 senderKID 값을 이용하여 신청자 인증을 위한 정보를 가져온다.
  // 3. 메시지가 MAC으로 보호되어 있고, header의 sender값이 null이 아닌 경우(rr메시지인 경우에 한함)
  //    DB로부터 header의 sender값을 이용하여 신청자 인증을 위한 정보와 인증서 폐지 신청 처리를 위한 정보를 가져온다.

  // 0. sender fields가 올바른지 확인
  if (_reqMessage->header->sender->select != GeneralName_directoryName)
  {
    /*# ERROR: Error Message 전송(badDataFormat : 잘못된 header) */
    /*# LOG : sender가 directoryName이 아님  */
    CMPSendErrorException e(LOG_CAMSGD_INVALID_SENDER_TYPE_N);
    e.addOpt("sender의 chioce 값",
        _reqMessage->header->sender->select - 1);
    throw e;
  }
  if (AlgNid_CheckSigAlg(_reqMessage->header->protectionAlg->algorithm->nid))
  {
    // 1. 서명으로 보호되어 있는 경우
    // 1.1. 메시지로부터 신청자 이름(sender name)을 얻음
    char senderDN[512];
    if (::Name_SprintLine(
      senderDN, sizeof(senderDN), _reqMessage->header->sender->choice.directoryName) < 0)
    {
      /*# ERROR: Error Message 전송(badDataFormat : 잘못된 header) */
      /*# LOG : sender값 해석 실패  */
      CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_RESOLVE_SENDER_N);
      e.addOpt(
        "sender 값(DER Encoded)",
        reinterpret_cast<ASN *>(_reqMessage->header->sender));
      throw e;
    }
    // 1.2. 신청자의 정보 및 인증서 가져오기
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
        /*# ERROR : Error Message 전송(signerNotTrusted(draft) : sender를 찾을 수 없음) */
        /*# LOG : sender값을 이용하여 요청자 정보를 찾는데 실패  */
        CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_FIND_SENDER_INFO_N);
        e.addOpt("요청자 DN", senderDN);
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
      /*# ERROR : Error Message 전송(signerNotTrusted(draft) : 서명을 검증하기 위한 sender 인증서 가져오기 실패) */
      /*# LOG : sender 인증서 검증 실패  */
      CMPSendErrorException e(LOG_CAMSGD_SENDER_NOT_TRUSTED_N);
      e.addOpt("요청자 DN", senderDN);
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
      /*# ERROR : Error Message 전송(signerNotTrusted(draft) :
          서명을 검증하기 위한 sender 인증서 가져오기 실패) */
      /*# LOG : sender 인증서 검증 실패  */
      CMPSendErrorException e(LOG_CAMSGD_SENDER_NOT_TRUSTED_N);
      e.addOpt("요청자 DN", senderDN);
      throw e;
    }
    _senderAuthInfo.reset(senderAuthInfo, ASN_Delete);

    // 1.3. 신청자의 인증서 검증(Not implemented)
    /*# NOTE : 최초로 발급하는 경우는 상호 인증 CA 자체의 인증서로 검증하는 것도 있을 필요가 있을지 검토할 것 */
  }
  else if (_reqMessage->header->protectionAlg->algorithm->nid
    == NID_passwordBasedMac)
  {
    if (_reqMessage.get()->header->sender->choice.directoryName->
      choice.rdnSequence->size == 0)
    {
      // 2. 메시지가 MAC으로 보호되어 있고, header의 sender값이 null인
      //    경우(reference number 사용한 경우)
      //    (ir, ccr, genm 메시지인 경우에 한함)
      if (_reqMessage.get()->body->select != PKIBody_ir &&
        _reqMessage.get()->body->select != PKIBody_ccr &&
        _reqMessage.get()->body->select != PKIBody_genm)
      {
        /*# ERROR: Error Message 전송(wrongIntegrity : 잘못된 요청) */
        /*# LOG : 잘못된 protection 방식(Reference number 사용)  */
        CMPSendErrorException e(LOG_CAMSGD_WRONG_INTEGRITY_REFNUM_N);
        e.addOpt("PKIBody의 choice 값",
            _reqMessage.get()->body->select - 1);
        throw e;
      }
      if (_reqMessage.get()->header->senderKID == NULL)
      {
        /*# ERROR : Error Message 전송(badRequest : 잘못된 header) */
        /*# LOG : senderKID 값이 존재하지 않음 */
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
          /*# ERROR : Error Message 전송(signerNotTrusted(draft) : 권한 검사 실패) */
          /*# LOG : 주어진 reference number에 해당하는 정보를 찾는데 실패 */
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
        /*# ERROR : Error Message 전송(signerNotTrusted(draft) : refnum 허용기간 불일치 */
        /*# LOG : Reference number가 유효하지 않음 */
        CMPSendErrorException e(LOG_CAMSGD_REFNUM_NOT_AVAILABLE_N);
        e.addOpts(
          "Reference number : %s, Reference number 유효기간 : %t부터 %t까지",
          refnum, timeSDate, timeEDate);
        throw e;
      }

      try
      {
        sender = dynamic_cast<Issac::DB::DBAuth *>(senderAuth.get())->getSubject();
      }
      catch (DBSelectException)
      {
        /*# ERROR : Error Message 전송(systemFailure(draft) : DB integrity 문제) */
        /*# LOG : PKIEntityAuth(PKIAuthorityAuth) 테이블의 SID로 해당 요청자 정보를 찾는데 실패 */
        CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_FIND_SENDER_BY_SID_N);
        e.addOpts(
          "Reference number : %s, 요청자 SID : %s",
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

      _removeRefnum = true;      // 종료후에 reference number를 삭제
    }
    else
    {
      // 3. 메시지가 MAC으로 보호되어 있고, header의 sender값이 null이 아닌 경우(rr메시지인 경우에 한함)
      if (_reqMessage.get()->body->select != PKIBody_rr)
      {
        /*# ERROR: Error Message 전송(badRequest : 잘못된 요청) */
        /*# LOG : 잘못된 protection 방식(RevPassPhrase 사용)  */
        CMPSendErrorException e(LOG_CAMSGD_WRONG_INTEGRITY_REVPASS_N);
        e.addOpt("PKIBody의 choice 값", _reqMessage.get()->body->select-1);
        throw e;
      }
      // 3.1. 메시지로부터 신청자 이름(sender name)을 얻음
      char senderDN[512];
      if (::Name_SprintLine(
        senderDN, sizeof(senderDN),
        _reqMessage->header->sender->choice.directoryName) < 0)
      {
        /*# ERROR: Error Message 전송(badDataFormat : 잘못된 header) */
        /*# LOG : sender값 해석 실패  */
        CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_RESOLVE_SENDER_N);
        e.addOpt(
          "sender 값(DER Encoded)",
          reinterpret_cast<ASN *>(_reqMessage->header->sender));
        throw e;
      }
      // 3.2. 신청자의 정보 및 인증서 가져오기
      std::ostringstream ost;
      ost << "DN='" << senderDN << "'";

      DBObjectSharedPtr sender;
      try
      {
        sender = DBEntity::select(ost.str().c_str());
      }
      catch (DBException)
      {
        // 1.2.1. PKIEntity 테이블에 정보가 없는 경우
        // CA는 revPassPhrase를 통한 폐지를 보안상 지원하지 않음
        /*# ERROR : Error Message 전송(signerNotTrusted(draft) : sender를 찾을 수 없음) */
        /*# LOG : sender값을 이용하여 요청자 정보를 찾는데 실패  */
        CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_FIND_SENDER_INFO_N);
        e.addOpt("요청자 DN", senderDN);
        throw e;
      }

      if (static_cast<DBEntity *>(sender.get())->revpass.empty())
      {
        /*# ERROR : Error Message 전송(signerNotTrusted(draft) : revPassPhrase가 등록되어 있지 않음) */
        /*# LOG : revPassPhrase가 등록되어 있지 않음 */
        CMPSendErrorException e(LOG_CAMSGD_REVPASS_NOT_REGISTERED_N);
        e.addOpt("요청자 DN", senderDN);
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
    /*# ERROR: Error Message 전송(알수없는 protectionAlg: badAlg) */
    /*# LOG : 알 수 없는 방식의 protection 방식 */
    CMPSendErrorException e(LOG_CAMSGD_UNKNOWN_PROTECTIONALG_N);
    e.addOpt(
      "요청 메시지의 header 값(DER Encoded)",
      reinterpret_cast<ASN *>(_reqMessage.get()->header));
    throw e;
  }
}

}
