#ifndef _SENDMAIL_
#define _SENDMAIL_

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

int SendMail(const char *senderDomain, 
             const char *senderAddr, const char *recvAddr, 
             const char *host, int port, 
             const char *title, const char *content);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
