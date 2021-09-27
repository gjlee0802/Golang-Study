/** @file er_define.h
    @brief error 및 debug 관련 정의

    borrow from CIS 'base_define.h'
*/

#ifndef _ER_DEFINE_H_
#define _ER_DEFINE_H_

#ifndef USHRT_MAX
#  include <limits.h>
#endif


#ifndef SUCCESS
#define SUCCESS 0
#endif /* SUCCESS */

#ifndef FAIL
#define FAIL -1
#endif /* FAIL */

/* borrow from 'glib.h' */
#  if defined (__GNUC__) && !defined (__STRICT_ANSI__) && !defined (__cplusplus)
#    define _START    (void)(
#    define _END      )
#  else
#    if (defined (sun) || defined (__sun__))
#      define _START  if (1)
#      define _END    else (void)0
#    else
#      define _START  do
#      define _END    while (0)
#    endif
#  endif

#ifndef VERIFY
#ifdef NDEBUG
#define VERIFY(f) ((void)(f))
#else
#define VERIFY(f) assert(f)
#endif // #ifdef NDEBUG
#endif // #ifndef VERIFY

/* assertion code for error handling */
#ifndef DEBUG

#define _ER_PRINT(expr) 

#define ER_IF(expr)

#define ER_RET_IF(expr)           if(expr) return FAIL
#define ER_RET_VAL(val)           return (val)
#define ER_RET_VAL_IF(expr, val)  if(expr) return (val)
#define ER_RET_VOID_IF(expr)      if(expr) return
#define ER_RET_NULL_IF(expr)      if(expr) return NULL


#define ER_RETX_IF(expr, line)           if(expr) _START { \
  line; return FAIL; } _END
#define ER_RETX_VAL(val, line)                    _START { \
  line; return (val); } _END
#define ER_RETX_VAL_IF(expr, val, line)  if(expr) _START { \
  line; return (val); } _END
#define ER_RETX_VOID_IF(expr, line)      if(expr) _START { \
  line; return; } _END
#define ER_RETX_NULL_IF(expr, line)      if(expr) _START { \
  line; return NULL; } _END

#else /* DEBUG */

#include <stdio.h>
#ifdef WIN32
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif

#ifdef __GNUC__

#define _ER_PRINT(expr) \
                  fprintf(stderr, "ERROR: '%s', file %s, line %d(%s).\n\n",\
                          #expr, __FILE__, __LINE__, __PRETTY_FUNCTION__)

#define ER_IF(expr)  if(expr) \
                           _ER_PRINT(expr)

#define ER_RET_IF(expr)           if(expr) _START {\
                           _ER_PRINT(expr); \
            return FAIL; } _END    

#define ER_RET_VAL(val)    _START {\
            fprintf(stderr, "ERROR: file %s, line %d(%s), '%s' returned.\n\n",\
                    __FILE__, __LINE__, __PRETTY_FUNCTION__ , #val);\
                           return (val); } _END

#define ER_RET_VAL_IF(expr, val)  if(expr) _START {\
            fprintf(stderr, "ERROR: '%s', file %s, line %d(%s), '%s' returned.\n\n",\
                    #expr, __FILE__, __LINE__, __PRETTY_FUNCTION__ , #val);\
                           return (val); } _END

#define ER_RET_NULL_IF(expr)      if(expr) _START {\
                           _ER_PRINT(expr); \
                           return NULL; } _END

#define ER_RET_VOID_IF(expr)      if(expr) _START {\
                           _ER_PRINT(expr); \
                           return; } _END

#define ER_RETX_IF(expr, line)           if(expr) _START { line;\
                           _ER_PRINT(expr); \
            return FAIL; } _END    

#define ER_RETX_VAL(val, line)  _START { line;\
            fprintf(stderr, "ERROR: file %s, line %d(%s), '%s' returned.\n\n",\
                    __FILE__, __LINE__, __PRETTY_FUNCTION__ , #val);\
                    return (val); } _END

#define ER_RETX_VAL_IF(expr, val, line)  if(expr) _START { line;\
            fprintf(stderr, "ERROR: '%s', file %s, line %d(%s), '%s' returned.\n\n",\
                    #expr, __FILE__, __LINE__, __PRETTY_FUNCTION__ , #val);\
                           return (val); } _END

#define ER_RETX_NULL_IF(expr, line)      if(expr) _START { line;\
                           _ER_PRINT(expr); \
                           return NULL; } _END

#define ER_RETX_VOID_IF(expr, line)      if(expr) _START { line;\
                           _ER_PRINT(expr); \
                           return; } _END

#else /* !__GNUC__ */

#define _ER_PRINT(expr) \
                  fprintf(stderr, "ERROR: '%s', file %s, line %d.\n\n",\
                          #expr, __FILE__, __LINE__)

#define ER_IF(expr)  if(expr) \
                           _ER_PRINT(expr)

#define ER_RET_IF(expr)           if(expr) _START {\
                           _ER_PRINT(expr); \
            return FAIL; } _END    

#define ER_RET_VAL(val)  _START {\
            fprintf(stderr, "ERROR: file %s, line %d, '%s' returned.\n\n",\
                    __FILE__, __LINE__, #val); return (val); } _END

#define ER_RET_VAL_IF(expr, val)  if(expr) _START {\
            fprintf(stderr, "ERROR: '%s', file %s, line %d, '%s' returned.\n\n",\
                    #expr, __FILE__, __LINE__, #val);\
                           return (val); } _END

#define ER_RET_NULL_IF(expr)      if(expr) _START {\
                           _ER_PRINT(expr); \
                           return NULL; } _END

#define ER_RET_VOID_IF(expr)      if(expr) _START {\
                           _ER_PRINT(expr); \
                           return; } _END

#define ER_RETX_IF(expr, line)           if(expr) _START { line;\
                           _ER_PRINT(expr); \
            return FAIL; } _END    

#define ER_RETX_VAL(val, line)  _START { line;\
            fprintf(stderr, "ERROR: file %s, line %d, '%s' returned.\n\n",\
                    __FILE__, __LINE__, #val); return (val); } _END

#define ER_RETX_VAL_IF(expr, val, line)  if(expr) _START { line;\
            fprintf(stderr, "ERROR: '%s', file %s, line %d, '%s' returned.\n\n",\
                    #expr, __FILE__, __LINE__, #val);\
                           return (val); } _END

#define ER_RETX_NULL_IF(expr, line)      if(expr) _START { line;\
                           _ER_PRINT(expr); \
                           return NULL; } _END

#define ER_RETX_VOID_IF(expr, line)      if(expr) _START { line;\
                           _ER_PRINT(expr); \
                           return; } _END

#endif /* __GNUC__ */

#endif /* DEBUG */



#endif /* _ER_DEFINE_H_ */

