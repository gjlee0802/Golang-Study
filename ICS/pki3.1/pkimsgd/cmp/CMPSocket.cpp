// CMPSocket.cpp: implementation of the CMPSocket class.
//
//////////////////////////////////////////////////////////////////////


#include <cassert>
#include <sstream>
#include <boost/shared_ptr.hpp>
#include <boost/scoped_array.hpp>

#include "asn1.h"
#include "pkimessage.h"

#include "Trace.h"

#include "CMPSocket.hpp"
#include "cis_cast.hpp"

using namespace std;
using namespace boost;

namespace Issac
{

CMPSocket::CMPSocket(SOCKET sock) : Socket(sock)
{
}

CMPSocket::CMPSocket(const Socket& sock) : Socket(sock)
{
}

CMPSocket::~CMPSocket()
{
}

void CMPSocket::sendPKIMessage(PKIMessage *msg)
{
  boost::shared_ptr<ASNBuf> buf(ASN_EncodeDER(msg), ASNBuf_Delete);
  if (buf.get() == NULL)
    throw Exception("CMP::sendMessage-> ASN_EncodeDER error");

  unsigned long len = htonl(buf->len + 1);
  unsigned char flag = 0x00;

  send(reinterpret_cast<void *>(&len), sizeof(len));
  send(reinterpret_cast<void *>(&flag), sizeof(flag));
  send((void *)(buf->data), buf->len);
}

#define MAX_MESSAGE_LEN (10 * 1024 * 1024)  // 10 M 이상의 PKI 메시지는 없음

PKIMessage *CMPSocket::recvPKIMessage() // must be freed by ASN_Delete
{
  unsigned long len;      // Big-endian length of message
  unsigned long hlen;     // Platform-specific endian length of message
  unsigned char flag;

  try
  {
    recv(&len, sizeof(len));
    hlen = ntohl(len) - 1; /* -1 : flag length */
    recv(&flag, sizeof(flag));
  }
  catch (...)
  {
    throw Exception(E_CMPSOCKET_FAIL_TO_RECV_MESSAGE);
  }

  if (hlen > MAX_MESSAGE_LEN)
    throw Exception(E_CMPSOCKET_MESSAGE_TOO_LONG);

  if (flag != 0x00)
    throw Exception(E_CMPSOCKET_INVALID_PROTOCOL);

  boost::scoped_array<char> buf(new char[hlen + 1]);
  try
  {
    recv((void *)buf.get(), hlen);
  }
  catch (...)
  {
    throw Exception(E_CMPSOCKET_FAIL_TO_RECV_MESSAGE);
  }

  ASNBuf asnBuf;
  ASNBuf_SetP(&asnBuf, buf.get(), hlen);
  PKIMessage *msg = ASN_New(PKIMessage, &asnBuf);

  if (msg == NULL)
    throw Exception(E_CMPSOCKET_INVALID_PKI_MESSAGE);

  return msg;
}

}
