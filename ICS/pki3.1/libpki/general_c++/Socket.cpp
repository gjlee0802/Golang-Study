// Socket.cpp: implementation of the Socket class.
//
//////////////////////////////////////////////////////////////////////


#include <cassert>
#include <sstream>

#include "base_define.h"

#include "Socket.hpp"
#include "Trace.h"

namespace Issac
{

using namespace std;
using namespace boost;

#define E_S_SOCKET_NOT_INITIALIZED          "socket was not initialized"
#define E_S_SOCKET_RESOLVE_HOSTNAME         "can't resolve hostname"
#define E_S_SOCKET_CREATE_SOCKET            "can't create socket"
#define E_S_SOCKET_CONNECT                  "can't connect socket"
#define E_S_SOCKET_WRITE                    "can't write socket"
#define E_S_SOCKET_READ                     "can't read socket"
#define E_S_SOCKET_BIND                     "해당 port는 이미 사용중입니다."
#define E_S_SOCKET_ACCEPT                   "can't accept socket"
#define E_S_SOCKET_HAS_REFERENCE            "can't detach referenced socket"
#define E_S_SOCKET_BAD_LENGTH_HEADER        "can recv negative length"

#define TMPLOG "/tmp/libpki.log"

#define THROW_IF_NOT_INITIALIZED   _START \
  if (!_sock.get()) { \
    TRACE_LOG(TMPLOG, PRETTY_TRACE_STRING); \
    throw SocketError(E_S_SOCKET_NOT_INITIALIZED); \
  } _END

Socket::Socket(SOCKET sock) 
{
  _setNew(sock);
}

Socket::Socket(std::string ip, int port)
{
  connect(ip, port);
}

Socket::~Socket()
{
  close();
  // 소멸되어 주위의 reference count가 하나 감소하는 것이 아니라
  // close() 구현에 의해 close 순간 주위의 reference count가 하나 감소하고
  // 소멸하는 순간 자신이 1인 상태에서 그냥 소멸한다.
}

SOCKET Socket::handle() 
{ 
  if (_sock.get())
    return *(_sock.get());
  else
    return INVALID_SOCKET;
}

void Socket::_setNew(SOCKET sock)
{
  close();

  if (sock != INVALID_SOCKET)
  {
    _sock.reset(new SOCKET);
    *(_sock.get()) = sock;
  }
  else
  {
    _sock.reset();
  }
}

const std::string Socket::getPeerName() const
{
  THROW_IF_NOT_INITIALIZED;

  char buf[256];
  buf[0] = 0;
  if (!_sock.get())
    throw SocketError("in Socket::getPeerName: _sock is destroyed");

  if (::GetPeerName(buf, *(_sock.get())))
    throw SocketError("GetPeerName error");
  return buf;
}

void Socket::connect(string ip, int port)
{
  SOCKET sock = ::SocketConnect(ip.c_str(), port);

  if (sock == E_SOCK_RESOLVE_HOSTNAME)
    throw SocketError(E_S_SOCKET_RESOLVE_HOSTNAME);
  else if (sock == E_SOCK_CREATE_SOCKET)
    throw SocketError(E_S_SOCKET_CREATE_SOCKET);
  else if (sock == E_SOCK_CONNECT)
    throw SocketError(E_S_SOCKET_CONNECT);
  else if (sock == INVALID_SOCKET)
    throw SocketError(E_S_SOCKET_CONNECT);

  _setNew(sock);
}

void Socket::send(const std::string &buf) 
{
  THROW_IF_NOT_INITIALIZED;

  if (SendN(*(_sock.get()), (void *)(buf.c_str()), buf.size()) == -1)
    throw SocketError(E_S_SOCKET_WRITE);
}

void Socket::send(const void *buf, size_t len) 
{
  THROW_IF_NOT_INITIALIZED;

  if (SendN(*(_sock.get()), buf, len) == -1)
    throw SocketError(E_S_SOCKET_WRITE);
}

size_t Socket::recv(void *buf, size_t len)
{
  THROW_IF_NOT_INITIALIZED;

  size_t ret = RecvN(*(_sock.get()), buf, len);
  if (ret != len)
  {
		if(ret>0)
    	throw SocketError(E_S_SOCKET_READ);
		else
			throw SocketError(E_S_SOCKET_NOT_INITIALIZED);
  }

  return ret;
}

size_t Socket::recv(std::string& buf, size_t len)
{
  THROW_IF_NOT_INITIALIZED;

  buf.resize(len);
  size_t ret = RecvN(*(_sock.get()), (void *)(buf.c_str()), len);
  if (ret != len)
  {
		if(ret>0)
    	throw SocketError(E_S_SOCKET_READ);
		else
			throw SocketError(E_S_SOCKET_NOT_INITIALIZED);
  }

  buf.resize(ret);

  return ret;
}

void Socket::close()
{
  if (_sock.unique())
    CloseSocket(*(_sock.get()));
}

void Socket::attach(SOCKET sock)
{
  _setNew(sock);
}

// 러페런스가 있으면 detach 못하도록 하는 것이 합당하다.
SOCKET Socket::detach()
{
  if (!_sock.unique())
  {
    throw logic_error(E_S_SOCKET_HAS_REFERENCE);
  }

  THROW_IF_NOT_INITIALIZED;

  SOCKET sock = *(_sock.get());
  _sock.reset();

  return sock;
}

void Socket::listen(int port)
{
  SOCKET sock = ::BindAndListen(port);
  if (sock == INVALID_SOCKET)
    throw SocketError(E_S_SOCKET_BIND);

  _setNew(sock);
}

void Socket::sendLengthAndData(const std::string &buf)
{
  BT32 rlen;
  rlen = htonl(buf.size());

  send(&rlen, sizeof(rlen));

  if (buf.size())
    send(buf);
}

std::string Socket::extractBufFromLengthAndDataBuf(std::string recvBuf)
{
  return recvBuf.substr(sizeof(BT32), recvBuf.size() - sizeof(BT32));
}

string Socket::makeLengthAndDataBuf(std::string sendBuf)
{
  if (sendBuf.empty())
    return "";

  BT32 rlen = sendBuf.size();
  rlen = htonl((BT32)rlen);
  string ret(static_cast<char *>((void *)&rlen), sizeof(rlen));
  ret += sendBuf;
  return ret;
}

void Socket::sendLengthAndData(const void *buf, size_t len)
{
  BT32 rlen;
  rlen = htonl((BT32)len);

  send(&rlen, sizeof(rlen));

  if (len && buf)
    send(buf, len);
}

void Socket::recvLengthAndData(string &buf)
{
  BT32 rlen;
  
  recv(&rlen, sizeof(rlen));

  if (ntohl(rlen) < 0)
      throw SocketError(E_S_SOCKET_BAD_LENGTH_HEADER);

  size_t len = (size_t)(ntohl(rlen));

  if (len == 0)
    return;

  recv(buf, len);
}

Socket Socket::accept(struct sockaddr *addr, socklen_t *addrlen)
{
  THROW_IF_NOT_INITIALIZED;

  SOCKET sock;
  if ((sock = ::accept(*(_sock.get()), addr, addrlen)) == INVALID_SOCKET)
    throw SocketError(E_S_SOCKET_ACCEPT);
  return (Socket(sock));
}

} // end of namespace
