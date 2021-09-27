#ifndef _PKI_LOG_H_
#define _PKI_LOG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <time.h>

#include "hmac.h"

#define     MAC_KEY_LENGTH  16
#define     MAC_DATA_LEN    20
#define     LOG_LINE_SIZE   8192

typedef struct _PKI_LOG_CONTEXT
{
	char    group[12];
	char    ipAddress[40];
	char    system[40];
	char    process[40];
	int		  type;
	char    header[512];
	char    date[24];
	char    fileName[1024];
	char    passwd[24];
	BYTE    key[MAC_KEY_LENGTH];
	BYTE    hmac[MAC_DATA_LEN];
	BWT		  hmacLen;
	HmacContext    ctx;
	long    size;
} PKI_LOG_CONTEXT;

PKI_LOG_CONTEXT *
ISSACLog_Init(
    char *group, char *sysstem, char *process, 
    int type, char *logDir, char *logName, char *passwd
    );

int	
ISSACLog_Write(PKI_LOG_CONTEXT* ctx, int err, const char *fmt, ...);

void 
ISSACLog_Close(PKI_LOG_CONTEXT* ctx);

int 
ISSACLog_CheckHMAC(const char *file, const char *date, const char *passwd);

long 
ISSACLog_Read(
  char *line, const char *file, const char *date, long *size);

int ISSACLog_GetHMAC(BYTE *hmac,  BWT *len, const char *fileName, int pos,
        const char *passwd);
#ifdef __cplusplus
}
#endif

#endif /* _ISSAC_LOG_H_ */
