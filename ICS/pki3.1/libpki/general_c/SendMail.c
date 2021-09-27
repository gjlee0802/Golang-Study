#include <sys/types.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include "SendMail.h"
#include "SocketHelper.h"
#include "er_define.h"

#ifndef MIN
#define MIN(x, y) ((x) > (y) ? (y) : (x))
#endif


/*
#if defined SOLARIS || defined HPUX || defined AIX || defined TRU64 
extern "C"
{
	int getdomainname(char *name, int namelen);
}
#endif
*/

#define XMIME "MIME-Version: 1.0\r\n" \
"Content-Type: text/plain; charset=\"ks_c_5601-1987\"\r\n" \
"X-Priority: 3 (Normal)\r\n" \
"X-MSMail-Priority: Normail\r\n" \
"X-Mailer: Penta Security Mailer v1.0\r\n" \
"Content-Transfer-Encoding: 8bit\r\n" \
"X-MIME-Autoconverted: from base64 to 8bit by Penta Security Mailer v1.0\r\n" \
"To: <%s>\r\nSubject: %s\r\n\r\n"

#define MAX_MESSAGE_LENGTH 1024

/* SMTP Sender와 Receiver간에 주고 받는 절차를 담당하는 함수 */
static int SMTP_SendAndRecv(int sock, char *msg)
{
	int recvlen;
	char* buf = malloc(strlen(msg) + 2);
	strncpy(buf, msg, strlen(msg) + 1);

	if (send(sock, msg, strlen(msg), 0) == -1)
	{
		free(buf);
		return -1;
	}
	if ((recvlen = recv(sock, msg, MAX_MESSAGE_LENGTH, 0)) == -1)
	{
		msg[recvlen] = '\0';
		free(buf);
		return -1;
	}
  free(buf);

	return 0;
}

int SendMail(const char *senderDomain, 
             const char *senderAddr, const char *recvAddr, 
             const char *host, int port, 
             const char *title, const char *content)
{
  SOCKET sock;
  char buf[MAX_MESSAGE_LENGTH];
	int ret = -1;
  int inret = 0;
  int i;

  ER_RET_IF(!senderDomain || !senderDomain || !recvAddr || !host ||
      port <= 0);

  ret = -1;
  do
  {
	  int recvlen;
	  if ((sock = SocketConnect(host, port)) < 0)
		  break;

	  if ((recvlen = recv(sock, buf, MAX_MESSAGE_LENGTH, 0)) == -1)
	  {
		  buf[recvlen] = '\0';
		  break;
	  }

	  memset(buf, 0, MAX_MESSAGE_LENGTH);
	  sprintf(buf, "HELO %s\r\n", senderDomain);

	  if (SMTP_SendAndRecv(sock, buf) == -1)
		  break;

	  memset(buf, 0, MAX_MESSAGE_LENGTH);
	  sprintf(buf, "MAIL From:<%s>\r\n", senderAddr); 
	  if (SMTP_SendAndRecv(sock, buf) == -1)
		  break;

	  memset(buf, 0, MAX_MESSAGE_LENGTH);
	  sprintf(buf, "RCPT TO:<%s>\r\n", recvAddr); 
	  if (SMTP_SendAndRecv(sock, buf) == -1)
		  break;

	  memset(buf, 0, MAX_MESSAGE_LENGTH);
	  sprintf(buf, "DATA\r\n");
	  if (SMTP_SendAndRecv(sock, buf )== -1 )
		  ret = -1;

    sprintf(buf, XMIME, recvAddr, title);
	  if (send(sock, buf, strlen(buf), 0) == -1)
	  {
		  buf[recvlen] = '\0';
		  break;
	  }
    /* 내용은 길수도 있으므로 잘라서 할당해서 보낸다. */
    // 먼저 제목을 보내고
    // 내용을 잘라서 보낸다.
    for (i = 0; i < strlen(content); i += MAX_MESSAGE_LENGTH - 1)
    {
      int copylen = MIN(MAX_MESSAGE_LENGTH - 1, strlen(content) - i);
      if (copylen <= 0)
        break;

      memset(buf, 0, MAX_MESSAGE_LENGTH);
      memcpy(buf, content + i, copylen);
	    if (send(sock, buf, strlen(buf), 0) == -1)
	    {
		    buf[recvlen] = '\0';
        inret = 1;
		    break;
	    }
    }
    if (inret == 1)
      break;

    strcpy(buf, "\r\n");
	  if (send(sock, buf, strlen(buf), 0) == -1)
	  {
		  buf[recvlen] = '\0';
		  break;
	  }
    // 종료한다.
    sprintf(buf, ".\r\n");
	  if (SMTP_SendAndRecv(sock, buf) == -1)
		  break;

	  memset(buf, 0, MAX_MESSAGE_LENGTH);
	  sprintf(buf, "QUIT\r\n");

	  if (SMTP_SendAndRecv(sock, buf) == -1)
		  break;

    ret = 0;
  } while (0);

	closesocket(sock);

  return ret;
}

