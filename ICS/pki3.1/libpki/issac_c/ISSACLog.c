/* standard headers */
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>

#ifdef WIN32
#include <io.h>
#include <sys/locking.h>
#include <winsock2.h>
#else
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <errno.h>
#endif

/* cis headers */
#include "sha1.h"
#include "pbkdf.h"

#include "ISSACLog.h"
#include "SocketHelper.h"
#include "TimeHelper.h"
#include "libc_wrapper.h"
#include "Trace.h"

#ifdef WIN32 
#define   DIR_DEL "\\"
#else
#define   DIR_DEL "/"
#endif


PKI_LOG_CONTEXT *
ISSACLog_Init(char *group, char *system, char *process, int type, 
    char *logDir, char *logName, char *passwd )
{
  PKI_LOG_CONTEXT	*ctx;
  time_t t;
  FILE	*fp;
  struct stat buf;
  char   host[64];
  char   addr[44];
  char   date[11];
  char   tmp[1024];
  char   line[LOG_LINE_SIZE];

  ER_RET_VAL_IF(
      (group == (char *)NULL) || (process == (char *)NULL) ||
      (logDir == (char *)NULL) || (passwd == (char *)NULL) ||
      (type == 0) || (logName == (char *)NULL) ||
      (group[0] == 0x00) || (process[0] == 0x00) ||
      (logDir[0] == 0x00) || (passwd[0] == 0x00) ||
      (logName[0] == 0x00), 
      NULL);

  gethostname(host, 128);

  ctx = (PKI_LOG_CONTEXT *)malloc(sizeof(PKI_LOG_CONTEXT));
  ER_RET_VAL_IF(ctx == NULL, NULL);

  sprintf(ctx->fileName, "%s", logDir);

  SOCKET_GetIPAddress(host, addr);

  if ((system != (char *)NULL) && (system[0] != 0x00))
  {
    sprintf(ctx->fileName, "%s" DIR_DEL "%s.%s.%s", ctx->fileName,
        group, system, addr);
    sprintf(ctx->header, "%s;%s;%s", group, system, addr);
  }
  else
  {
    sprintf(ctx->fileName, "%s" DIR_DEL "%s.%s.%s", ctx->fileName,
        group, host, addr);
    sprintf(ctx->header, "%s;%s;%s", group, host, addr);
  }

  sprintf(ctx->fileName, "%s.%s.%02d.%s", ctx->fileName,
      process, type, logName);
  sprintf( ctx->header, "%s;%s;%02d;%s", ctx->header,
      process, type, logName);
  ctx->type = type;

#ifndef NO_HMAC
  sprintf(ctx->passwd, "%s", passwd);
  PBKDF_PKCS5_1(ctx->key, MAC_KEY_LENGTH, ctx->passwd,
      (unsigned char *)PBKDF_DEFAULT_SALT, PBKDF_DEFAULT_SALT_LEN,
      PBKDF_DEFAULT_ITERATION, SHA1);

  HMAC_Initialize(&ctx->ctx, ctx->key, MAC_KEY_LENGTH, SHA1);

  memset(date, 0x00, sizeof(date));
  memset(ctx->date,0x00, sizeof(ctx->date));
  t = time((time_t *)NULL);
  Time_MakeString( t, date, "YYYYMMDD");
  sprintf(ctx->date, "%s", date);

  sprintf(tmp, "%s.%s", ctx->fileName, date);

  ER_RETX_VAL_IF((fp = fopen(tmp, "a+")) == NULL, NULL, free(ctx));
  ER_RETX_VAL_IF(write_lock(fileno(fp), 0, 0, 0) < 0, NULL, 
    (free(ctx), fclose(fp)));

  stat(tmp, &buf);
  if (buf.st_size > 0)
  {
    rewind(fp);
    while(1)
    {
      if( fgets( line, LOG_LINE_SIZE, fp ) == NULL )
      {
        break;
      }
      HMAC_Update( &ctx->ctx, (BYTE *)line, strlen(line) );
    }
    HMAC_Finalize(ctx->hmac, (BWT *)&ctx->hmacLen, &ctx->ctx);

    ctx->size = buf.st_size;
  }
  else
  { 
    ctx->size = 0;
  }

  fclose(fp);
#endif
  return ctx;
}

static void ReadFirst(PKI_LOG_CONTEXT *ctx, int fp, long size)
{
  return;

  long	len;
  char	buf[LOG_LINE_SIZE];
  long	tmp = 0;

  lseek(fp, ctx->size, SEEK_SET);
  tmp = ctx->size;

  while (tmp != size)
  {
    memset(buf, 0x00, sizeof(buf));
    if( (len = read( fp, buf, LOG_LINE_SIZE)) == 0 )
    {
      break;
    }
    HMAC_Update(&ctx->ctx, (BYTE *)buf, len);
    tmp = tmp + len;
  }
  HMAC_Finalize(ctx->hmac, (BWT *)&ctx->hmacLen, &ctx->ctx);
  return;
}

int ISSACLog_Write(PKI_LOG_CONTEXT *ctx, int errCode, const char *fmt, ...)
{
  va_list args;
  int			logfd;
  int			rec;
  time_t  t;
  struct stat	stbuf;
  FILE		*hmacfp;
  char		date[30];
  char		fileName[1024];
  char		hmacFileName[1024];
  char		buf[LOG_LINE_SIZE];
  char		tmp[LOG_LINE_SIZE];
  char		line[LOG_LINE_SIZE];
	int ret;
  
  memset( tmp, 0x00, sizeof(tmp) );
  memset( line, 0x00, sizeof(line) );

  va_start(args,fmt);

  t = time((time_t)NULL);
  Time_MakeString(t, date, "YYYYMMDD");
  sprintf(fileName, "%s.%s", ctx->fileName, date);

  /** fileName을 open 하고 "fileName.hmac"을 ctx에 담는다. **/
  sprintf(hmacFileName, "%s.hmac", fileName);
	logfd = open(fileName, O_RDWR|O_APPEND|O_CREAT, 0644);
	if(logfd < 0)
	{
		fprintf(stderr,"LOG FILE OPEN ERROR\n");
	}
  ER_RET_IF(logfd < 0);
  //ER_RET_IF((logfd = open(fileName, O_RDWR|O_APPEND|O_CREAT, 0644)) < 0);
  
  ret = write_lock(logfd, 0, 0, 0);
  if( ret < 0)
  {
	  fprintf(stderr,"LOG FILE WRITE LOCK ERROR\n");
	  fprintf(stderr,"%d %s",errno, strerror(errno));
  }
  ER_RETX_IF(ret < 0 , close(logfd));
  //ER_RETX_IF(write_lock(logfd, 0, 0, 0) < 0, close(logfd));
#ifndef NO_HMAC
  if (strncmp(ctx->date, date, 8) != 0)
  {
    memset(&ctx->ctx, 0x00, sizeof(HmacContext));
    memset(ctx->date, 0x00, sizeof(ctx->date));
    sprintf(ctx->date, "%s", date);
    HMAC_Initialize(&ctx->ctx, ctx->key, MAC_KEY_LENGTH, SHA1);
    ctx->size = 0;
  }

  fstat(logfd, &stbuf);
  if (ctx->size < stbuf.st_size)
  {
    ReadFirst(ctx, logfd, stbuf.st_size);
    ctx->size = stbuf.st_size;
  }
#endif
  Time_MakeString(t, date, "YYYY/MM/DD hh:mm:ss"); 
  /** line: Record header add **/
  sprintf(line, "%s;", ctx->header);

  /** line: Record header;err;date; **/
  if( ctx->type == 10 )
  {
    if( errCode == 0 )
    {
      sprintf(tmp, "%s;00;", date);
      memcpy( (char *)&line[strlen(line)], tmp, strlen(tmp) );
    }
    else
    {
      sprintf(tmp, "%s;%d;", date, errCode );
      memcpy( (char *)&line[strlen(line)], tmp, strlen(tmp) );
    }
  }
  else if( ctx->type == 20 )
  {
    sprintf(tmp, "%s;", date);
    memcpy((char *)&line[strlen(line)], tmp, strlen(tmp));
  }

  memset( buf, 0x00, sizeof(buf) );
  vsprintf(buf, fmt, args);
  /** 8.29 jhjung **/
  if (buf[strlen(buf) - 1] == 0x0a) buf[strlen(buf) - 1] = 0x00;

  memset(tmp, 0x00, sizeof(tmp));
  sprintf(tmp, "%s%s\n", line, buf);
  
  ret = write(logfd, tmp, strlen(tmp));
  if( ret < 0 )
  {
	  fprintf(stderr, "LOG WRITE ERROR \n");
  }
  //ER_RETX_IF(write(logfd, tmp, strlen(tmp)) < 0, close(logfd));
	ER_RETX_IF( ret < 0, close(logfd));
  
  
  
  close(logfd);
#ifndef NO_HMAC
  rec = strlen(tmp);
  hmacfp = fopen(hmacFileName, "wb");
  HMAC_Update(&ctx->ctx, (BYTE *)tmp, rec);
  HMAC_Finalize(ctx->hmac, (BWT *)&ctx->hmacLen, &ctx->ctx );
  write(fileno(hmacfp), ctx->hmac, ctx->hmacLen );
  fclose(hmacfp);

  ctx->size = ctx->size+rec;
#endif
  va_end(args);
  return 0;
}

/**
out : output
파일 이름과 읽어야 할 위치
처음 이라면 위치 값은 0, 다음 부터는 전에 읽었던 위치
date : YYYYMMDD
 **/
long ISSACLog_Read(
    char *out, const char *fileName, const char *date, long *size)
{
  FILE	*fp;
  char	buf[LOG_LINE_SIZE];
  char	dateFileName[1024];
  long	len;

  memset( buf, 0x00, sizeof(buf) );
  memset( out, 0x00, sizeof(out) );

  sprintf( dateFileName, "%s.%s", fileName, date );

  len = *size;
  fp = fopen( dateFileName, "r" );
  if( fp == NULL )
  {
    *size = 0;
    return -1;
  }
  fseek( fp, len, SEEK_SET );
  fgets( buf, LOG_LINE_SIZE, fp );
  if( strcmp(buf, "" ) == 0x00 )
  {
    *size = 0;
    fclose( fp );
    return -2;
  }
  fclose( fp );

  *size = strlen(buf);
  len = len + *size;
  strcpy( out, buf );
  return len;
}

int ISSACLog_CheckHMAC(const char *fileName, const char *date, 
    const char *passwd)
{
#ifndef NO_HMAC
  return 1;
#else
  FILE    *fp, *fph;
  char    line[LOG_LINE_SIZE];
  char    macFile[1024];
  char    dateFileName[1024];
  int     count=0;

  BYTE    bkey1[MAC_KEY_LENGTH];
  HmacContext ctx2 ;
  BYTE    hmac1[MAC_DATA_LEN];
  BWT     hmacLen1;

  sprintf( macFile, "%s.%s.hmac", fileName, date );
  sprintf( dateFileName, "%s.%s", fileName, date );

  if (access(dateFileName, F_OK) <0) return -1;

  fp= fopen( dateFileName, "a+");
  if( fp== NULL ) return -1;


  if( write_lock( fileno(fp), 0, 0, 0)< 0)
  {
    fclose(fp);
    return -4;
  }

  PBKDF_PKCS5_1( bkey1, MAC_KEY_LENGTH, passwd,
      (unsigned char *)PBKDF_DEFAULT_SALT, PBKDF_DEFAULT_SALT_LEN,
      PBKDF_DEFAULT_ITERATION, SHA1 );

  rewind(fp);
  HMAC_Initialize(&ctx2, bkey1, MAC_KEY_LENGTH, SHA1);
  while( 1 )
  {
    memset( line, 0x00, sizeof(line) );
    if( fgets( line, LOG_LINE_SIZE, fp) == NULL )
    {
      break;
    }
    HMAC_Update( &ctx2, (BYTE *)line, strlen(line) );
    count = count + strlen(line);
  }
  HMAC_Finalize(hmac1, &hmacLen1, &ctx2);

  fph = fopen(macFile, "rb" );
  if( fph == NULL )
  {
    fclose(fp);
    return -2;
  }
  fread( line, 1, MAC_DATA_LEN, fph );
  fclose( fph );

  fclose( fp);

  if( memcmp( hmac1, line, MAC_DATA_LEN ) == 0 )
  {
    return 1;
  }

  return -3;
#endif
}

int ISSACLog_GetHMAC(BYTE *hmac, BWT *len, const char *fileName, int pos, 
    const char *passwd)
{
#ifndef NO_HMAC
  FILE    *fp;
  char    line[LOG_LINE_SIZE];
  int     count=0;

  BYTE    bkey1[MAC_KEY_LENGTH];
  HmacContext ctx2 ;

  if (access(fileName, F_OK) <0) return -1;

  fp= fopen( fileName, "r");
  if( fp== NULL ) return -1;


  PBKDF_PKCS5_1( bkey1, MAC_KEY_LENGTH, passwd,
      (unsigned char *)PBKDF_DEFAULT_SALT, PBKDF_DEFAULT_SALT_LEN,
      PBKDF_DEFAULT_ITERATION, SHA1 );

  rewind(fp);
  HMAC_Initialize(&ctx2, bkey1, MAC_KEY_LENGTH, SHA1);
  while( 1 )
  {
    memset( line, 0x00, sizeof(line) );
    if( fgets( line, LOG_LINE_SIZE, fp) == NULL )
    {
      break;
    }
    HMAC_Update( &ctx2, (BYTE *)line, strlen(line) );
    count = count + strlen(line);
    if (count == pos)
      break;
  }
  HMAC_Finalize(hmac, len, &ctx2);
#endif
  return 1;
}

void ISSACLog_Close(PKI_LOG_CONTEXT *h)
{
  if( h != NULL )
  {
    free( h );
  }
}
