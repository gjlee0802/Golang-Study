// Socket.hpp: interface for the Socket class.
//             대부분 SocketHelper.h의 C++ wrapper이다.
//             하지만 예외처리가 들어있어 SocketHelper.h 
//             보다는 이것을 사용하기를 권한다. - 조현래
//
//////////////////////////////////////////////////////////////////////

#ifndef ISSAC_SOCKET_HPP
#define ISSAC_SOCKET_HPP

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <string>

#include <boost/shared_ptr.hpp>

#include "SocketHelper.h"
#include "Exception.hpp"

namespace Issac 
{

/**
 * Network 송/수신을 위한 class
 */
class SocketError : public Exception
{
public:
  SocketError(const std::string &s = 
    "Issac::SocketError") : Exception(s) {}
};

class Socket 
{
public:
  Socket(SOCKET sock = INVALID_SOCKET);
  Socket(std::string ip, int port);
  virtual ~Socket();

  SOCKET handle();

  /**
   * 기존의 소켓 핸들(SOCKET)로부터 인스턴스를 구성한다. 만약 이미 _sock이 
   * 연결되어 있으면 close하고 구성한다. attach한 소켓을 사용자가 따로 
   * closesocket(HANDLE)하면 안된다. 소멸자가 해 준다. 물론 Socket.close()
   * 는 해도 된다.
   */
  void attach(SOCKET sock); 

  /**
   * 소켓 핸들(SOCKET)을 인스턴스에서 분리한다. _sock은 INVALID_SOCKET로 설정
   * detach한 소켓을 사용자가 알아서 closesocket해야 한다.
   * @exception
   *  - logic_error : 레퍼런스가 있는 소켓을 detach한 경우
   */
  SOCKET detach();

  /**
   * 주어진 ip, port 에 접속한다.
   *
   * @exception
   *  - SocketError : 접속에 실패한 경우
   */
  void connect(std::string ip, int port);
  /**
   * 접속한 상대의 ip 주소 값을 리턴한다.
   */
  const std::string getPeerName() const;

  /**
   * 데이터를 len(혹은 buf.size())만큼 block해서 송신한다. 
   * 
   * @param
   *  - buf        (In) 송신할 데이터를 저장하는 버퍼
   *                    참고) std::string을 size()의 버퍼에 바이너리도
   *                          저장할 수 있다.
   *  - len        (In) 송신할 데이터의 길이
   * @exception
   *  - SocketError : 데이터 송신에 실패한 경우
   */
  virtual void send(const std::string &buf);
  virtual void send(const void *buf, size_t len);

  /**
   * data를 len 만큼 block해서 수신한다.
   *
   * @param
   *  - buf      (Out) 수신한 데이터를 저장할 버퍼
   *  - size     (In)  수신할 데이터의 길이 (이 길이를 수신할 때까지 block됨)
   * @return 
   *   수신한 데이터 길이
   * @exception
   *  - SocketError : 데이터 수신에 실패한 경우
   */
  virtual size_t recv(std::string& buf, size_t len);
  virtual size_t recv(void *buf, size_t len);

  /**
   * 접속을 close한다.
   */
  void close();

  /** 
   * 해당 포트에 바인드하고 리슨한다.
   * 이 소켓은 이후 accept 하거나 select해서 서버 소켓으로 활용한다.
   *
   * @exception
   *  - SocketError : bind 또는 listen에 실패한 경우
   */
  void listen(int port);

  /**
   * 데이터를 송신하기 전에 먼저 데이터 길이를 송신하고 그다음
   * 데이터를 len(혹은 buf.size())만큼 block해서 송신한다. 
   * 
   * @param
   *  - buf        (In) 송신할 데이터를 저장하는 버퍼
   *                    참고) std::string을 size()의 버퍼에 바이너리도
   *                          저장할 수 있다.
   *  - len        (In) 송신할 데이터의 길이
   * @exception
   *  - SocketError : 데이터 송신에 실패한 경우
   */
  virtual void sendLengthAndData(const std::string &buf);
  virtual void sendLengthAndData(const void *buf, size_t len);

  static std::string makeLengthAndDataBuf(std::string sendBuf);
  static std::string extractBufFromLengthAndDataBuf(std::string recvBuf);

  /**
   * 데이터의 길이를 수신하고 그 다음 그 길이만큼 block해서 수신한다.
   * 읽은 바이트 수는 buf.size() 하면 알 수 있다.
   *
   * @param
   *  - buf      (Out) 수신한 데이터를 저장할 버퍼
   * @exception
   *  - SocketError : 데이터 수신에 실패한 경우
   */
  virtual void recvLengthAndData(std::string& buf);

  /**
   * 커넥트된 소켓을 리턴한다. 이 함수를 호출하기 위해서는 현재
   * 소켓이 listen 상태이어야 한다.
   */
  Socket accept(struct sockaddr *addr, socklen_t *addrlen);


protected:
  boost::shared_ptr<SOCKET> _sock;

  virtual void _setNew(SOCKET sock);
};

} // end of namespace


#endif // ISSAC_SOCKET_HPP
