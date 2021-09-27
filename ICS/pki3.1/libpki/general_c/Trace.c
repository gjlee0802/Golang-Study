/**
 * @filePath      Trace.c
 *
 * @desc      Debug trace function
 * @author    Cho, Hyoen Rae(velvetfish@hotmail.com)
 * @since     2003.02.20
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "Trace.h"

#ifdef DEBUG

#define TRACE_BEGIN     "<TRACE>"
#ifdef _WIN32
  #define TRACE_END     "</TRACE>\r\n"
#else
  #define TRACE_END     "</TRACE>\n"
#endif

char ___b_[4096];

void Trace(const char* format, ...)
{
	va_list args;
  fprintf(stderr, TRACE_BEGIN);
	
  va_start(args, format);

	vfprintf(stderr, format, args);

	va_end(args);

  fprintf(stderr, TRACE_END);
}

void TraceLog(const char* filePath, const char* format, ...)
{
  char buf[4096];
  FILE *fp;
	va_list args;

  va_start(args, format);

	vsprintf(buf, format, args);

	va_end(args);

  if ((fp = fopen(filePath, "a")) != NULL)
  {
    fwrite(TRACE_BEGIN, sizeof(char), strlen(TRACE_BEGIN), fp);
    fwrite(buf, sizeof(char), strlen(buf), fp);
    fwrite(TRACE_END, sizeof(char), strlen(TRACE_END), fp);
    fclose(fp);
  }
}

#else

void Trace(const char* format, ...) {}
void TraceLog(const char* filePath, const char* format, ...) {}

#endif 

/////////////////////////////////////////////////////////////////////////////
