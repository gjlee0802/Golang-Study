/**
 * @file    CMP_checkSenderPrivilege.cpp
 *
 * @desc    요청자의 권한을 확인하는 helper 함수
 * @author  조현래(hrcho@pentasecurity.com)
 * @since   2002.05.10
 *
 * Revision History
 *
 * @date     2003.05.07 : Start
 *
 * 
 */

#include "x509com.h"

#include "DBSubject.hpp"
#include "CnK_define.hpp"

#include "CMP.hpp"
#include "CMPException.hpp"
#include "PKILogTableDefine.hpp"
#include "Trace.h"

#ifdef __CYGWIN__
#define TRACEFILE "/cygdrive/c/camsgd.log"
#else
#define TRACEFILE "/tmp/camsgd.log"
#endif

using namespace Issac;
using namespace Issac::DB;
using namespace std;

void CMP::checkSenderPrivilege(DBSubject *sender, DBSubject *certHolder)
{
  TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
  VERIFY(certHolder && sender); // 잘못된 parameter

  // 1. 신청자의 권한 검사
  if (::strcmp(certHolder->getDN().c_str(), sender->getDN().c_str()) != 0) 
  {
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    // 신청자와 요청자가 다른 경우
    DBEntity *e;
      
    if ((e = dynamic_cast<DBEntity*>(sender)) != NULL)
    {
      TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
      if (e->type != PKIDB_ENTITY_TYPE_RA)
      {
        TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
        // 1.1. 신청자가 RA가 아닌 경우
        if (e->sid != CA_MASTERADMIN_ENTITY_SID)
        {
          TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
          if (e->type == PKIDB_ENTITY_TYPE_ADMIN)
          {
            TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
            // 관리자 권한 검사
            if (::strcmp(certHolder->getType().c_str(), 
              PKIDB_AUTHORITY_TYPE_CROSS) == 0 ||
              ::strcmp(certHolder->getType().c_str(), 
              PKIDB_AUTHORITY_TYPE_SUB) == 0)
            {
              // 신청 대상이 CA인 경우
              if (::strstr(e->priv.c_str(), PKIDB_MANAGER_PRV_PKI_EDIT_AUTHORITY) == NULL)
                /*# ERROR : 해당 관리자에게 인증서 발급/폐지 신청을 요청할 권한이 없음 */
                throw CMPSendErrorException(LOG_CAMSGD_SENDER_NOT_AUTHORIZED_N);
            }
            else
            {
              // 요청 대상이 일반 사용자 혹은 관리자, RA인 경우
              if (::strcmp(certHolder->getType().c_str(), PKIDB_ENTITY_TYPE_ADMIN) == 0||
                ::strcmp(certHolder->getType().c_str(), PKIDB_ENTITY_TYPE_RA) == 0)
                // 요청 대상이 관리자 또는 RA인 경우 : PMM, RMM만이 요청할 권한이 있음.
                /*# ERROR : 해당 관리자에게 인증서 발급/폐지 신청을 요청할 권한이 없음 */
                throw CMPSendErrorException(LOG_CAMSGD_SENDER_NOT_AUTHORIZED_N);

              if (::strstr(e->priv.c_str(), PKIDB_MANAGER_PRV_PKI_ISSUE_CERT) == NULL)
                /*# ERROR : 해당 관리자에게 인증서 발급/폐지 신청을 요청할 권한이 없음 */
                throw CMPSendErrorException(LOG_CAMSGD_SENDER_NOT_AUTHORIZED_N);
            }
          }
          else
            /*# ERROR : Error Message 전송
                  (notAuthorized : 사용자는 다른 사용자의 인증서 발급을 요청할 수 없음) */
            throw CMPSendErrorException(LOG_CAMSGD_REQUESTED_BY_USER_N);
        } // else // PMM에게는 모든 권한이 허가되어 있음
      } // ::strcmp(e->type, PKIDB_ENTITY_TYPE_RA) != 0
      else 
      {
        TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
        // 1.2. 신청자가 RA인 경우
        // Base DN 제한을 벗어나지 않는지 검사
        if (!e->manroot.empty())
        {
          if (::strstr(certHolder->getDN().c_str(), e->manroot.c_str()) == NULL)
          {
            /*# ERROR : 해당 RA에게 해당 사용자에 대해 인증서 발급/폐지 신청을 요청할 권한이 없음 */
            CMPSendErrorException ex(LOG_CAMSGD_RA_NOT_AUTHORIZED_N);
            ex.addOpt("RA의 base DN", string(e->manroot));
            throw ex;
          }
        }
      }
    } // (e = dynamic_cast<DBEntity*>(sender)) != NULL
    else
      /*# ERROR : CA는 자신의 인증서에 대한 발급/폐지만을 요청할 수 있음 */
      throw CMPSendErrorException(LOG_CAMSGD_REQUESTED_BY_OTHERCA_N);
  } // else : 신청자 == 요청자이면 허가
  TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
}

