/**
 * @file    CMP_checkSenderPrivilege.cpp
 *
 * @desc    ��û���� ������ Ȯ���ϴ� helper �Լ�
 * @author  ������(hrcho@pentasecurity.com)
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
  VERIFY(certHolder && sender); // �߸��� parameter

  // 1. ��û���� ���� �˻�
  if (::strcmp(certHolder->getDN().c_str(), sender->getDN().c_str()) != 0) 
  {
    TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
    // ��û�ڿ� ��û�ڰ� �ٸ� ���
    DBEntity *e;
      
    if ((e = dynamic_cast<DBEntity*>(sender)) != NULL)
    {
      TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
      if (e->type != PKIDB_ENTITY_TYPE_RA)
      {
        TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
        // 1.1. ��û�ڰ� RA�� �ƴ� ���
        if (e->sid != CA_MASTERADMIN_ENTITY_SID)
        {
          TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
          if (e->type == PKIDB_ENTITY_TYPE_ADMIN)
          {
            TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
            // ������ ���� �˻�
            if (::strcmp(certHolder->getType().c_str(), 
              PKIDB_AUTHORITY_TYPE_CROSS) == 0 ||
              ::strcmp(certHolder->getType().c_str(), 
              PKIDB_AUTHORITY_TYPE_SUB) == 0)
            {
              // ��û ����� CA�� ���
              if (::strstr(e->priv.c_str(), PKIDB_MANAGER_PRV_PKI_EDIT_AUTHORITY) == NULL)
                /*# ERROR : �ش� �����ڿ��� ������ �߱�/���� ��û�� ��û�� ������ ���� */
                throw CMPSendErrorException(LOG_CAMSGD_SENDER_NOT_AUTHORIZED_N);
            }
            else
            {
              // ��û ����� �Ϲ� ����� Ȥ�� ������, RA�� ���
              if (::strcmp(certHolder->getType().c_str(), PKIDB_ENTITY_TYPE_ADMIN) == 0||
                ::strcmp(certHolder->getType().c_str(), PKIDB_ENTITY_TYPE_RA) == 0)
                // ��û ����� ������ �Ǵ� RA�� ��� : PMM, RMM���� ��û�� ������ ����.
                /*# ERROR : �ش� �����ڿ��� ������ �߱�/���� ��û�� ��û�� ������ ���� */
                throw CMPSendErrorException(LOG_CAMSGD_SENDER_NOT_AUTHORIZED_N);

              if (::strstr(e->priv.c_str(), PKIDB_MANAGER_PRV_PKI_ISSUE_CERT) == NULL)
                /*# ERROR : �ش� �����ڿ��� ������ �߱�/���� ��û�� ��û�� ������ ���� */
                throw CMPSendErrorException(LOG_CAMSGD_SENDER_NOT_AUTHORIZED_N);
            }
          }
          else
            /*# ERROR : Error Message ����
                  (notAuthorized : ����ڴ� �ٸ� ������� ������ �߱��� ��û�� �� ����) */
            throw CMPSendErrorException(LOG_CAMSGD_REQUESTED_BY_USER_N);
        } // else // PMM���Դ� ��� ������ �㰡�Ǿ� ����
      } // ::strcmp(e->type, PKIDB_ENTITY_TYPE_RA) != 0
      else 
      {
        TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
        // 1.2. ��û�ڰ� RA�� ���
        // Base DN ������ ����� �ʴ��� �˻�
        if (!e->manroot.empty())
        {
          if (::strstr(certHolder->getDN().c_str(), e->manroot.c_str()) == NULL)
          {
            /*# ERROR : �ش� RA���� �ش� ����ڿ� ���� ������ �߱�/���� ��û�� ��û�� ������ ���� */
            CMPSendErrorException ex(LOG_CAMSGD_RA_NOT_AUTHORIZED_N);
            ex.addOpt("RA�� base DN", string(e->manroot));
            throw ex;
          }
        }
      }
    } // (e = dynamic_cast<DBEntity*>(sender)) != NULL
    else
      /*# ERROR : CA�� �ڽ��� �������� ���� �߱�/�������� ��û�� �� ���� */
      throw CMPSendErrorException(LOG_CAMSGD_REQUESTED_BY_OTHERCA_N);
  } // else : ��û�� == ��û���̸� �㰡
  TRACE_LOG(TRACEFILE, PRETTY_TRACE_STRING);
}

