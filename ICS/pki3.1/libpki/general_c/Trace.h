/**
 * @file      Trace.h
 *
 * @desc      debug trace function
 * @author    Cho, Hyoen Rae (velvetfish@hotmail.com)
 * @since     2003.02.20
 */

#ifndef _TRACE_H_
#define _TRACE_H_

#include <stdio.h>

#include "base_define.h"
#include "er_define.h"

#ifdef __cplusplus
extern "C" {
#endif

void Trace(const char* format, ...);
void TraceLog(const char *filePath, const char* format, ...);

#ifdef DEBUG

extern char ___b_[4096];

#ifndef TRACE
#define TRACE                     Trace
#endif
#ifndef TRACE_LOG
#define TRACE_LOG                 TraceLog
#endif

#ifdef __GNUC__
  #ifndef PRETTY_TRACE_STRING   
  #define PRETTY_TRACE_STRING     (sprintf(___b_, "file %s, line %d(%s)",\
                                    __FILE__, __LINE__, __PRETTY_FUNCTION__), ___b_)
  #endif
#else
  #ifndef PRETTY_TRACE_STRING   
  #define PRETTY_TRACE_STRING     (sprintf(___b_, "file %s, line %d",\
                                    __FILE__, __LINE__), ___b_)
  #endif
#endif

#ifdef __GNUC__
  #ifndef PRETTY_TRACE_STRING_N 
  #define PRETTY_TRACE_STRING_N   (sprintf(___b_, "file %s, line %d(%s)\n",\
                                    __FILE__, __LINE__, __PRETTY_FUNCTION__), ___b_)
  #endif
#else
  #ifndef PRETTY_TRACE_STRING_N   
  #define PRETTY_TRACE_STRING_N   (sprintf(___b_, "file %s, line %d\n",\
                                    __FILE__, __LINE__), ___b_)
  #endif
#endif

#else // !_DEBUG

#define TRACE 1 ? (void)0 : Trace
#define TRACE_LOG 1 ? (void)0 : Trace
#define PRETTY_TRACE_STRING ((char *)0)
#define PRETTY_TRACE_STRING_N ((char *)0)

#endif // !_DEBUG

#ifdef __cplusplus
}
#endif
#endif // _TRACE_H_
