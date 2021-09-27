/**
 * @file    CMP_processCertRequest.cpp
 *
 * @desc    인증서 요청 메시지(ir, cr, kur, ccr)을 처리하는 function
 * @author   조현래(hrcho@pentasecurity.com)
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
    /*# ERROR: Error Message 전송(badDataFormat : 잘못된 Body) */
    /*# LOG: 인증서 발급 요청 메시지의 Body가 비어있음 */
    throw CMPSendErrorException(LOG_CAMSGD_EMPTY_ISSUEREQUEST_BODY_N);

  /**
   * 신청 대상에 대한 정보는 PKIEntity/PKIAuthority table의 데이터와
   * 신청 대상에 대해 할당되어 있는 PKIPolicy table의 데이터를 가져오는 구분된다.
   * 신청 대상에 대한 정보를 가져오는 과정은 다음의 3가지로 구분된다.
   *
   * 1. 요청의 protection이 reference number와 secret value으로 생성된 MAC protection인 경우
   *  - 신청 대상은 요청자와 동일하므로 요청자 정보로부터 신청 대상에 대한 정보를 생성한다.
   * 2. 요청의 요청자의 서명을 이용한 protection이고, 요청자랑 신청 대상이 같은 경우
   *  - 요청자 정보로부터 신청 대상에 대한 정보를 생성한다.
   * 3. 요청의 요청자의 서명을 이용한 protection이고, 요청자랑 신청 대상이 다른 경우
   *  - 인증서 신청 메시지 내의 DN 값을 이용하여 신청 대상에 대한 정보를 DB로 부터 가져온다.
   *    단, 요청자가 RA인 경우에는 DB내에 신청 대상에 대한 정보가 존재하지 않으므로,
   *    요청자의 RA의 정보와 인증서 신청 메시지 내의 정보를 이용하여 신청 대상에 대한 정보를 생성한다.
   */
  switch (_senderAuthInfo->select)
  {
  case PKISenderAuthInfo_secretValue :
  {
    // 요청자와 요청 대상이 동일
    _certHolder = _sender;
    // 인증서 신청 메시지 내의 DN값이 올바른지 확인
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
            /*# ERROR : Error Message 전송(notAuthorized : 사용자는 다른 사용자의 인증서 발급을 요청할 수 없음) */
            /*# LOG : 사용자는 다른 사용자의 인증서 발급을 요청할 수 없음 */
            CMPSendErrorException e(LOG_CAMSGD_REQUESTED_BY_USER_N);
            e.addOpt("발급 대상 DN", certHolderDN);
            throw e;
          }
        } // 올바른 형식의 Name이 아닌 경우(무시)
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
      /*# ERROR: Error Message 전송(badDataFormat : certTemplate의 subject값은 존재해야 함) */
      /*# LOG : 인증서 발급 요청 메시지 안의 certTemplate의 subject 값이 존재하지 않음 */
      CMPSendErrorException e(LOG_CAMSGD_MISSING_SUBJECT_IN_CERTTEMPLATE_N);
      e.addOpt("PKIBody의 choice 값", _reqMessage.get()->body->select-1);
      throw e;
    }
    // CertReqMessages 내의 모든 요청이 동일한 발급 대상에 대한 인증서 요청인지 확인
    for (int reqIdx = 1; reqIdx < certReqMessages->size; ++reqIdx)
    {
      if (certReqMessages->member[reqIdx]->certReq->certTemplate->subject !=
        NULL)
      {
        if (::Name_Compare(
          certHolderDNName,
          certReqMessages->member[reqIdx]->certReq->certTemplate->subject) != SUCCESS)
        {
          /*# ERROR: Error Message 전송(badRequest : certTemplate의 subject값은 모두 같아야 함) */
          /*# LOG : 인증서 발급 요청 메시지 안의 certTemplate의 subject 값들이 서로 동일하지 않음 */
          CMPSendErrorException e(LOG_CAMSGD_MULTIPLE_SUBJECT_N);
          e.addOpts(
            "발급 대상 DN(1) : %s, 발급 대상 DN(2) : %s",
            type2string<Name*>(certHolderDNName).c_str(),
            type2string<Name*>(
              certReqMessages->member[reqIdx]->certReq->certTemplate->subject).c_str());
          throw e;
        }
      } // else : 2번째 request부터는 subject 생략 가능
    }

    char certHolderDN[512];
    ::Name_SprintLine(certHolderDN, sizeof(certHolderDN), certHolderDNName);
    if (dynamic_cast<DBSubject*>(_sender.get())->getDN() ==
      certHolderDN)
    {
      // 신청자와 신청 대상이 같음
      _certHolder = _sender;
    }
    else
    {
      // 신청자와 신청 대상이 다름
      DBEntity *entity = dynamic_cast<DBEntity *>(_sender.get());
      if (entity == NULL)
      {
        /*# ERROR: Error Message 전송(notAuthorized : CA는 다른 사용자의 인증서 발급을 요청할 수 없음) */
        /*# LOG : 타 CA는 다른 사용자의 인증서 발급을 요청할 수 없음 */
        CMPSendErrorException e(LOG_CAMSGD_REQUESTED_BY_OTHERCA_N);
        e.addOpt("발급 대상 DN", certHolderDN);
        throw e;
      }

      if (entity->type != PKIDB_ENTITY_TYPE_RA)
      {
        // 신청 대상이 현 도메인의 사용자인 경우

        // 신청자의 정보 가져오기
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
            /*# ERROR : Error Message 전송(badRequest: 신청 대상을 찾을 수 없음) */
            /*# LOG : 발급 대상에 대한 정보를 찾는데 실패 */
            CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_FIND_SUBJECT_INFO_N);
            e.addOpt("발급 대상 DN", certHolderDN);
            throw e;
          }
        }
        _certHolder = certHolder;
      }
      else
      {
        // 신청 대상이 RA 도메인의 사용자인 경우
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
  // 1. 신청자의 권한 검사
  checkSenderPrivilege(dynamic_cast<DBSubject*>(_sender.get()),
    dynamic_cast<DBSubject*>(_certHolder.get()));

  // 2. 발급 대상의 권한 검사
  DBAuthority *authority;
  DBEntity *entity;
  Issac::DB::DBRAEntity *ra;

  if ((authority = dynamic_cast<DBAuthority*>(_certHolder.get()) ) != NULL)
  {
    // 상호 인증기관인 경우 발급이 허가되어 있는지 검사
    if (authority->type == PKIDB_AUTHORITY_TYPE_CROSS)
    {
      if (authority->crstype != PKIDB_CROSSCERT_BY_CERT &&
        authority->crstype != PKIDB_CROSSCERT_BY_CERT_N_CTL)
        /*# ERROR: Error Message 전송(badRequest : 발급이 허가되지 않음) */
        /*# LOG : 인증서 발급이 허가되지 않은 상호 인증 기관(CTL 사용) */
        throw CMPSendErrorException(LOG_CAMSGD_SUBJECT_NOT_AUTHORIZED_N);
    }
    else if (authority->type != PKIDB_AUTHORITY_TYPE_SUB)
      /*# ERROR: Error Message 전송(badRequest : 발급이 허가되지 않음) */
      /*# LOG : 현 CA의 인증서 발급 요청 */
      throw CMPSendErrorException(LOG_CAMSGD_REQUEST_FOR_THIS_CA_CERT_N);
  }
  else if ((ra = dynamic_cast<Issac::DB::DBRAEntity*>(_certHolder.get())) != NULL)
  {
    // RA DBEntity인 경우
    // 신청한 사용자의 DN값이 기존 사용자들의 DN값과 겹치는지 검사
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
        /*# ERROR: 동일한 DN값을 갖는 사용자가 존재 */
        /*# LOG : 동일한 DN 값을 갖는 기존 사용자가 존재 */
        CMPSendErrorException e(LOG_CAMSGD_DUPLICATE_DN_N);
        e.addOpt("발급 대상 DN", ra->dn);
        throw e;
      }
      else ::DBI_ResultFree(sel);
    }

    // 해당 신청 대상에게 기존에 발급된 인증서가 있는 경우, 동일한 RA로부터 발급된 것인지 확인
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
        /*# ERROR: 동일한 DN값을 갖는 사용자가 존재 */
        /*# LOG : 동일한 DN 값을 갖는 기존 사용자가 존재 */
        CMPSendErrorException e(LOG_CAMSGD_DUPLICATE_DN_N);
        e.addOpt("발급 대상 DN", ra->dn);
        throw e;
      }
      else ::DBI_ResultFree(sel);
    }
  }
  else
  {
    entity = boost::polymorphic_downcast<DBEntity *>(_certHolder.get());
    // 발급 유효기간 검사
    if (entity->vlimit != 0 && entity->vlimit < ::time(NULL))
    {
      /*# ERROR: Error Message 전송(badRequest : 발급 대상의 유효기간 만료 */
      /*# LOG : 발급 대상의 유효기간 만료 */
      CMPSendErrorException e(LOG_CAMSGD_SUBJECT_VLIMIT_EXPIRED_N);
      e.addOpts("발급 대상의 유효기간 : %t까지", entity->vlimit);
      throw e;
    }
  }

  // 3. 기타 권한 검사
  //   - ccr은 발급 대상이 상호 인증 CA 인 경우에 한하여 신청 가능
  if (_reqMessage->body->select == PKIBody_ccr)
  {
    if (dynamic_cast<DBAuthority *>(_certHolder.get()) == NULL)
    {
      /*# ERROR: Error Message 전송(badRequest : 발급이 허가되지 않음) */
      /*# LOG : ccr 메시지는 상호 인증시에만 사용됨 */
      CMPSendErrorException e(LOG_CAMSGD_CCR_USED_FOR_NON_AUTHORITY_N);
      e.addOpt("발급 대상 DN",
        dynamic_cast<DBEntity*>(_certHolder.get())->dn);
      throw e;
    }
  }
}

}
