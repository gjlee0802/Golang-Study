// CMPSocket.hpp: interface for the CMPSocket class.
//
//////////////////////////////////////////////////////////////////////

#ifndef ISSAC_CMP_SOCKET_HPP
#define ISSAC_CMP_SOCKET_HPP

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <string>
#include <boost/detail/shared_count.hpp>

typedef struct _PKIMessage PKIMessage;

#include "Socket.hpp"

namespace Issac {

// what()으로 얻을 수 있는 값 중 다음은 미리 정의할 만 한다.
#define E_CMPSOCKET_INVALID_FLAG "CMPSocket-> Exception: invlaid flag"
#define E_CMPSOCKET_INVALID_PROTOCOL "CMPSocket-> Exception: invlaid protocol"
#define E_CMPSOCKET_FAIL_TO_RECV_MESSAGE \
                    "CMPSocket-> Exception: fail to recv message"
#define E_CMPSOCKET_INVALID_PKI_MESSAGE \
                    "CMPSocket-> Exception: invalid pki message"
#define E_CMPSOCKET_MESSAGE_TOO_LONG \
                    "CMPSocket-> Exception: pkimessage is too long"

class CMPSocket : public Socket
{
public:
  CMPSocket(SOCKET sock = -1);
  CMPSocket(const Socket& sock);
  virtual ~CMPSocket();
  void sendPKIMessage(PKIMessage *msg);
  PKIMessage *recvPKIMessage();
};

} // end of namespace


#endif // ISSAC_CMP_SOCKET_HPP
