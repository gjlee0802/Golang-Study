/**
 * @file    CMP_sendAndRecvMessageWithCA.cpp
 *
 * @desc    CA���� ��û �޽����� ������ ���� �޽����� �����ϴ� function
 * @author  ������(hrcho@pentasecurity.com)
 * @since   2002.05.10
 *
 * Revision history
 *
 * @date    2002.05.10 : Start
 */

// cis headers
#include "x509com.h"
#include "pkimessage.h"

// pkilib headers
#include "Trace.h"
#include "DBSubject.hpp"

#include "CMP.hpp"
#include "CMPException.hpp"
#include "PKILogTableDefine.hpp"
#include "Log.hpp"

using namespace Issac;
using namespace std;
using namespace Issac::DB;

namespace Issac
{

void CMP::sendAndRecvMessageWithCA() // related to _reqMessageToCA, _resMessageFromCA
{
  // 1. CA�� ����
  // 1.1. CA ������ ������
  DBAuthority *ca = dynamic_cast<DBAuthority *>(
    DBObjectBase::getCA().get());

  // 1.2. CA�� ����
  try
  {
    _sockToCA.connect(ca->ip, ca->port);
  }
  catch (...)
  {
    CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_CONNECT_CA_N);
    e.addOpts("CA�� IP �ּ� : %s, ��Ʈ��ȣ : %i", ca->ip.c_str(), ca->port);
    throw e;
  }

  // 2. CA�� ��û �޽��� ����
  try
  {
    _sockToCA.sendPKIMessage(_reqMessageToCA.get());
  }
  catch (...)
  {
    /*# Exception : CA�� ��û �޽��� ���� ���� */
    throw CMPSendErrorException(LOG_CAMSGD_FAIL_TO_SEND_REQUEST_TO_CA_N);
  }

  // 3. CA�κ��� ���� �޽��� ����
  PKIMessage *resMessage;
  try
  {
    resMessage = _sockToCA.recvPKIMessage();
  }
  catch (...)
  {
    /*# Exception : CA�κ��� ���� �޽��� ���� ���� */
    throw CMPSendErrorException(LOG_CAMSGD_FAIL_TO_RECV_REPONSE_FROM_CA_N);
  }
  _resMessageFromCA.reset(resMessage, ASN_Delete);
}

}
