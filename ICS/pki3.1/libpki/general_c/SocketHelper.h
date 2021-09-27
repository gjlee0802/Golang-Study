/* 
   Copyright (C) 2000 PENTA SECURITY SYSTEMS, INC.
   All rights reserved

   THIS IS UNPUBLISHED PROPRIETARY 
   SOURCE CODE OF PENTA SECURITY SYSTEMS, INC.
   The copyright notice above does not evidence any actual or 
   intended publication of such source code.

   Filename : SocketHelper.h
*/

#ifndef _SOCKET_HELPER_H_
#define _SOCKET_HELPER_H_

#include <stdlib.h>
#ifdef WIN32
  #include <winsock.h>
  #pragma comment(lib, "ws2_32.lib")
#else
  #include <sys/socket.h>
  #include <unistd.h>
  #include <netdb.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WIN32 
#define SOCKET         int
#define INVALID_SOCKET (-1)
#define closesocket(s) close(s)
#else
#define socklen_t int
#endif

// WIN32 WSAStartup
int SOCKET_Init();
#define SocketInit SOCKET_Init
#ifdef WIN32
  #define SOCKET_Cleanup  WSACleanup()
#else
  #define SOCKET_Cleanup 
#endif

/**
 * 주어진 ip와 port값을 이용하여 socket을 생성하여 서버와 연결한 뒤 리턴한다.
 *
 * @param *ip   (In) 서버의 ip 값
 * @param  port (In) 서버의 port 값
 *
 * @return
 *  - 성공시 해당 socket 값, 실패시 음수값 리턴
 * @see SocketClose
 */
enum
{
  E_SOCK_RESOLVE_HOSTNAME = -200,  /**< Host 이름 해석 실패 */
  E_SOCK_CREATE_SOCKET,            /**< Socket 생성 실패 */
  E_SOCK_CONNECT,                  /**< 연결 실패 */
};

SOCKET SOCKET_Connect(const char *ip, int port);
#define SocketConnect SOCKET_Connect

/**
 * socket값으로부터 요청자의 주소 값을 얻는다.
 *
 * @param *szPeerName (Out) 주소 값이 저장될 버퍼, 실패시에는 공백문자가 저장된다.
 * @param  sock       (In)  socket
 * @return
 *    - 0     : 성공
 *    - -1    : 실패
 */
int SOCKET_GetPeerName(char *peerName, SOCKET sock);
#define GetPeerName SOCKET_GetPeerName

/** 
 * 해당 포트에 바인드하고 리슨한 소켓을 리턴한다.
 * 이 소켓은 이후 accept 하거나 select해서 서버 소켓으로 활용한다.
 * @return 
 *   -1              : 실패
      socket fd      : 성공
 */
SOCKET SOCKET_BindAndListen(int port);
#define BindAndListen SOCKET_BindAndListen
/** 
 * host명으로부터 ip값을 얻는다.
 */
void SOCKET_GetIPFromHost(char *ip, const char *host);
#define GetIPFromHost SOCKET_GetIPFromHost
#define GetIpFromHost SOCKET_GetIPFromHost
/**
 * 루프를 돌며 len 만큼 읽는다. 성공해도 상대가 적게 보낸 경우 
 * len 만큼 못읽을 경우도 있다.
 * @return 
 *   -1              : 실패
      읽은 바이트 수 : 성공
 */
int SOCKET_RecvN(SOCKET fd, void *buf, size_t len);
#define RecvN SOCKET_RecvN

/**
 * 루프를 돌며 len 만큼 보낸다. 성공한 경우 반드시 len만큼 보내며
 * 0을 리턴한다.
 * @return 
 *   -1     : 실패
      0     : 성공
 */
int SOCKET_SendN(SOCKET fd, const void *buf, size_t len);
#define SendN SOCKET_SendN

/**
 * fd로 길이에 해당하는 len을 먼저 보내고 그 다음 buf를 SendN으로 보낸다.
 *
 * @return
 *    - 0     : 성공
 *    - -1    : 실패
 */
int SOCKET_SendBuf(SOCKET fd, const char *buf, size_t len);
#define SendBuf SOCKET_SendBuf

/**
 * fd로 길이에 해당하는 바이트를 읽고 해석한다음 다시 그 길이만큼  
 * RecvN으로 읽어서 malloc해서 리턴한다. *buf는 사용해 free해야 한다.
 *
 * @return
 *    - 0     : 성공
 *    - -1    : 실패
 */
int SOCKET_RecvBuf(SOCKET fd, char **buf, size_t *len);
#define RecvBuf SOCKET_RecvBuf

/**
 * 루프를 돌면서 확실하게 닫는다.
 * 
 */
void SOCKET_Close(SOCKET sock);
#define CloseSocket SOCKET_Close

/**
 * 도메인 네임을 주면 ip 주소를 포맷해서 반환한다.
 * 만약 로컬의 아이피를 알고 싶으면 
 * char hostname[1024];char ip[128];
 * gethostname(hostname, 1024);GetIPAddress(hostname, ip);
 * 
 * @return
 *    - 0     : 성공
 *    - -1    : 실패
 */

int SOCKET_GetIPAddress(const char *hostname, char *ip);
#define GetIPAddress SOCKET_GetIPAddress

#ifdef __cplusplus
}
#endif

#endif /* _SOCKET_DEFINE_H_ */

