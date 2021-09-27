#ifndef _TIME_HELPER_H_
#define _TIME_HELPER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <time.h>

#include "TimeHelper.h"

/* YYYYMMDD hhmmss **/
char *Time_MakeString(time_t t, char *out, const char *format);

time_t Time_MakeTime(const char *str, const char *format);

#ifdef __cplusplus
}
#endif

#endif
