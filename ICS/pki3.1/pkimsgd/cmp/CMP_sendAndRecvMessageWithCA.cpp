/**
 * @file    CMP_sendAndRecvMessageWithCA.cpp
 *
 * @desc    CA에게 요청 메시지를 보내고 응답 메시지를 수신하는 function
 * @author  조현래(hrcho@pentasecurity.com)
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
  // 1. CA에 접속
  // 1.1. CA 정보를 가져옴
  DBAuthority *ca = dynamic_cast<DBAuthority *>(
    DBObjectBase::getCA().get());

  // 1.2. CA에 접속
  try
  {
    _sockToCA.connect(ca->ip, ca->port);
  }
  catch (...)
  {
    CMPSendErrorException e(LOG_CAMSGD_FAIL_TO_CONNECT_CA_N);
    e.addOpts("CA의 IP 주소 : %s, 포트번호 : %i", ca->ip.c_str(), ca->port);
    throw e;
  }

  // 2. CA에 요청 메시지 전송
  try
  {
    _sockToCA.sendPKIMessage(_reqMessageToCA.get());
  }
  catch (...)
  {
    /*# Exception : CA로 요청 메시지 전송 실패 */
    throw CMPSendErrorException(LOG_CAMSGD_FAIL_TO_SEND_REQUEST_TO_CA_N);
  }

  // 3. CA로부터 응답 메시지 수신
  PKIMessage *resMessage;
  try
  {
    resMessage = _sockToCA.recvPKIMessage();
  }
  catch (...)
  {
    /*# Exception : CA로부터 응답 메시지 수신 실패 */
    throw CMPSendErrorException(LOG_CAMSGD_FAIL_TO_RECV_REPONSE_FROM_CA_N);
  }
  _resMessageFromCA.reset(resMessage, ASN_Delete);
}

}
