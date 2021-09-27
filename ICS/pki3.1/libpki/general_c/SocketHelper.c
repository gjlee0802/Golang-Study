/**
 * @file     SocketHelper.h
 *
 * @desc     기본적인 소켓 C 래퍼
 * @author   조현래 (hrcho@pentasecurity.com)
 * @since    2001.10.29
 *
 */

#include <stdio.h>
#include <string.h>
#include <errno.h> 

#include "base_define.h"

#include "SocketHelper.h"
#include "er_define.h"

#ifndef INADDR_NONE
#define INADDR_NONE     0xffffffff
#endif

#ifdef WIN32
#define write(x, y, z) send((x), (y), (z), 0)
#define read(x, y, z) recv((x), (y), (z), 0)
#endif

int SOCKET_GetPeerName(char *peerName, SOCKET sock)
{
  int ret;
  int len;
  struct sockaddr_in addr;

  if (peerName == NULL)
    return -1;

  peerName[0] = '\0';
  len = sizeof(addr);
  ret =  getpeername(sock, (struct sockaddr*)&addr, &len);
  if (ret == -1 ||
     len != sizeof(addr))
    return -1;

  strcpy(peerName, inet_ntoa(addr.sin_addr));

  return 0;
}

void SOCKET_GetIPFromHost(char *ip, const char *host)
{
  struct hostent *hent;
  struct in_addr in;

#ifdef  WIN32
  hent = gethostbyname(host);
  memcpy(&in.s_addr, hent->h_addr_list[0], sizeof(in.s_addr));
#else
  hent = gethostbyname(host);
  endhostent();
  memcpy(&in.s_addr, hent->h_addr_list[0], sizeof(in.s_addr));
#endif
  sprintf(ip, "%s", inet_ntoa(in));
  return;
}

int SOCKET_Init()
{
#ifdef WIN32
  WSADATA  wsaData;
  ER_RET_IF(WSAStartup(MAKEWORD(2, 0), &wsaData) != 0);
  
  ER_RETX_IF(LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 0, 
    WSACleanup());
#endif
  return 0;
}

SOCKET SOCKET_Connect(const char *ip, int port)
{
  SOCKET sock;
  struct sockaddr_in serv_addr;
  struct hostent  *hent;
#ifdef _WIN32
  unsigned long   inaddr;
#else
  in_addr_t inaddr;
#endif
  int error;

  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family  = AF_INET;
  serv_addr.sin_port    = htons((short)port);

  if ((inaddr = inet_addr(ip)) != INADDR_NONE) 
    memcpy(&serv_addr.sin_addr, &inaddr, sizeof(inaddr));
  else
  {
    if ((hent = gethostbyname(ip)) == NULL)
      return E_SOCK_RESOLVE_HOSTNAME;
    memcpy (&serv_addr.sin_addr, hent->h_addr, hent->h_length);
  }

  sock  = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
  
  ER_RET_VAL_IF(sock == INVALID_SOCKET, E_SOCK_CREATE_SOCKET);
  
  error = connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
  ER_RET_VAL_IF(error == -1, E_SOCK_CONNECT);

  return sock;
}

#define MAX_EMPTY_LOOP 20
int SOCKET_SendN(SOCKET fd, const void *buf, size_t len)
{
  int	lefts;
  int	writtens;
  const char *ptr; 
  short emptyCount = 0;

  ptr = buf; 
  lefts = len;

  while (lefts > 0 && emptyCount < MAX_EMPTY_LOOP) 
  {
    if ((writtens = write(fd, ptr, lefts)) < 0) 
    {
      if (errno == EINTR)
      {
        ++emptyCount;
        writtens = 0;
      }
      else 
      {
        return (-1);
      }
    }
    else if (writtens == 0)
    {
      ++emptyCount;
    }

    lefts -= writtens;
    ptr += writtens;
  }

  return (lefts == 0 ? 0 : -1);
}

int SOCKET_RecvN(SOCKET fd, void *buf, size_t len)
{
  int lefts, reads;
  char *ptr = buf;
  short emptyCount = 0;

  lefts = len;
  while (lefts > 0 && emptyCount < MAX_EMPTY_LOOP) 
  {
    if ((reads = read(fd, ptr, lefts)) < 0)
    {
      if (errno == EINTR) 
      {
        ++emptyCount;
        reads = 0;
      }
      else
      {
        return (-1);
      }
    }
    else if (reads == 0)
    {
      ++emptyCount;
    }

    lefts -= reads;
    ptr += reads;
  }

  return (len - lefts);
}

int SOCKET_SendBuf(SOCKET fd, const char *buf, size_t len)
{
  BT32 rlen;
  rlen = htonl((BT32)len);

  ER_RET_IF(SOCKET_SendN(fd, &rlen, sizeof(BT32)) == -1);

  if (len > 0 && buf)
  {
    ER_RET_IF(SOCKET_SendN(fd, buf, len) == -1);
  }

  return 0;
}

int SOCKET_RecvBuf(SOCKET fd, char **buf, size_t *len)
{
  BT32 rlen;

  ER_RET_IF(SOCKET_RecvN(fd, &rlen, sizeof(BT32)) != sizeof(BT32));

  ER_RET_IF(ntohl(rlen) < 0);

  *len = (BT32)(ntohl(rlen));

  if (*len == 0)
    return 0;

  ER_RET_IF(*len < 0);

  *buf = (char *)malloc(*len + 1);
  if (!buf)
    return -1;
  *(*buf + *len) = 0;

  ER_RET_IF(SOCKET_RecvN(fd, *buf, *len) == -1);

  return 0;
}

SOCKET SOCKET_BindAndListen(int port)
{
  struct sockaddr_in addr;
	int		 flag;

  SOCKET fd = socket(AF_INET, SOCK_STREAM, 0);

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port); 
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  flag = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &flag, 
    sizeof (flag));

  ER_RETX_IF(0 != bind(fd, (struct sockaddr*)&addr, sizeof(addr)), 
    closesocket(fd));

  ER_RETX_IF(0 != listen(fd, SOMAXCONN), 
    closesocket(fd));

  return fd;
}

void SOCKET_Close(SOCKET sock)
{
  if (sock >= 0)
  {
    while (closesocket(sock) < 0)
    {
      if (errno != EINTR) 
        break;
    }
  }
}

int SOCKET_GetIPAddress(const char *hostname, char *ip)
{
  struct hostent *host;
 
  host = gethostbyname(hostname);
  if (host)
  {
		int i = -1;
	  while ( host->h_addr_list[++i] != NULL )
	  {
      sprintf(ip, "%hu.%hu.%hu.%hu",
          (unsigned char)host->h_addr_list[i][0],
          (unsigned char)host->h_addr_list[i][1],
          (unsigned char)host->h_addr_list[i][2],
          (unsigned char)host->h_addr_list[i][3]);
				
			if ( 0 == strcmp(ip, "127.0.0.1" ) )
		    continue;
			else
				break;
    }
  }
  else
  {
    ip[0] = 0;
    return -1;
  }
#ifndef WIN32
  endhostent() ;
#endif
  return 0;
}

