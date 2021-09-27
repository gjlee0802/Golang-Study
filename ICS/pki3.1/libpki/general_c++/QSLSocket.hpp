#ifndef _QSL_SOCKET_H_
#define _QSL_SOCKET_H_

#include "Socket.hpp"

// forward declarations for cis
typedef struct _QSLSession QSLSession;
typedef struct _Certificate Certificate;
typedef struct _PrivateKeyInfo PrivateKeyInfo;

namespace Issac
{

class QSLSocketError : public SocketError
{
public:
  QSLSocketError(const std::string &s = 
    "Issac::QSLSocketError") : SocketError(s) {}
};

class QSLSocket : public Socket
{
public :
  QSLSocket(SOCKET sock = -1);
  QSLSocket(const Socket& sock);
  virtual ~QSLSocket();

  /**
   * connect 되어 있는 서버에 세션을 요청한다.
   * @param
   *  - cert (in)     : 요청자의 인증서
   *  - priKey (in)   : 요청자의 비공개키
   * @exception
   *  - QSLSocketError : 세션 생성에 실패한 경우
   */
  void initClientSession(const Certificate *cert, const PrivateKeyInfo *priKey);

  /**
   * sql 커넥션을 맺기전에 사용자가 제시한 인증서의 dn, ser을 받아온다.
   */
  void recvRequester(std::string &dn, std::string &ser);
  /**
   * 주어진 dn에 대해 커넥션을 맺을 지 판단하여 내용을 전해 준다.
   * ok가 true이면 맺는다는 뜻.
   */
  void reply(const std::string reply, bool ok = true); 

  /**
   * accept 되어 있는 소켓에서 클라이언트의 세션 요청에 응답한다.
   * 이 때 클라이언트의 인증이 이루어 진다.
   * @param
   *  - cert (in)     : 요청자의 인증서
   * @exception
   *  - QSLSocketError : 세션 생성에 실패한 경우
   */
  void initServerSession(const Certificate *cert);

  virtual void sendLengthAndData(const void *buf, size_t len);
  virtual void sendLengthAndData(const std::string &buf);
  virtual void recvLengthAndData(std::string &recvBuf);

protected :
  void _sendQSLHeader();
  void _recvQSLHeader();
  boost::shared_ptr<QSLSession> _session;
};

} // end of namespace Issac

#endif // _QSL_SOCKET_H_

