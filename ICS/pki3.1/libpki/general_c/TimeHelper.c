#include <stdlib.h>
#include <string.h>

#include "TimeHelper.h"

/* YYYYMMDD hhmmss **/
char *Time_MakeString(time_t t, char *out, const char *format)
{

  int         index = 0;
  int         leng;
  const char *ptr;
  struct tm   stm;

  leng = strlen(format);

  stm = *localtime(&t);

  if (leng < 0) return NULL;

  memset(out, 0, leng + 1);

  for (index = 0; index < leng ;)
  {
    switch (format[index])
    {
      case 's':
        {
          if (format[index + 1] != 's')
          {
            out[index] = format[index];
            index ++;
            break;
          };
          out[index] = (stm.tm_sec / 10 ) + 0x30;
          out[index + 1] = (stm.tm_sec % 10 ) + 0x30;

          index = index + 2;
          break;
        }
      case 'm':
        {
          if (format[index + 1] != 'm')
          {
            out[index] = format[index];
            index ++;
            break;
          };
          out[index] = (stm.tm_min / 10 ) + 0x30;
          out[index + 1] = (stm.tm_min % 10 ) + 0x30;
          index = index + 2;
          break;
        };
      case 'h':
        {
          if (format[index + 1] != 'h')
          {
            out[index] = format[index];
            index ++;
            break;
          };
          out[index] = (stm.tm_hour / 10 ) + 0x30;
          out[index + 1] = (stm.tm_hour % 10 ) + 0x30;
          index = index + 2;
          break;
        };
      case 'D':
        {
          if (format[index + 1] != 'D')
          {
            out[index] = format[index];
            index ++;
            break;
          };
          out[index] = (stm.tm_mday / 10 ) + 0x30;
          out[index + 1] = (stm.tm_mday % 10 ) + 0x30;
          index = index + 2;
          break;
        };
      case 'M':
        {
          if (format[index + 1 ] != 'M')
          {
            out[index] = format[index];
            index ++;
            break;
          };
          out[index] = ((stm.tm_mon + 1) / 10 ) + 0x30;
          out[index + 1] = ( (stm.tm_mon + 1)  % 10 ) + 0x30;
          index = index + 2;
          break;
        };
      case 'Y':
        {
          ptr = &format[index];
          if (memcmp(ptr ,"YYYY", 4) == 0)
          {
            stm.tm_year = stm.tm_year + 1900;

            out[index + 2] = (stm.tm_year % 100 )/10 + 0x30;
            out[index + 3] = (stm.tm_year % 100 )%10 + 0x30;

            out[index] = ((stm.tm_year / 100 )/10) + 0x30;
            out[index + 1] = ((stm.tm_year / 100 ) %10)  + 0x30;

            index = index + 4;
            break;
          }
          if (format[index + 1 ] != 'Y')
          {
            out[index] = format[index];
            index ++;
            break;
          };

          stm.tm_year = stm.tm_year + 1900;

          out[index] = (stm.tm_year % 100 )/10 + 0x30;
          out[index + 1] = (stm.tm_year % 100 )/10 + 0x30;

          index = index + 2;
          break;
        };
      default :
        {
          out[index] = format[index];
          index ++;
        };
    }
  }
  return out;
}


time_t Time_MakeTime(const char *str, const char * format)
{

  struct tm   stm;
  int         index = 0;
  int         leng;
  const char *ptr;

  leng = strlen(format);
  memset(&stm, 0, sizeof(stm));

  if (leng < 0) return 0;

  for (index = 0; index < leng ;)
  {

    switch (format[index])
    {
      case 's':
        {
          if (format[index + 1] != 's')
          {
            index ++;
            break;
          };
          stm.tm_sec =
            ((str[index] - 0x30) * 10) +
            (str[index + 1] - 0x30);
          index = index + 2;
          break;
        }
      case 'm':
        {
          if (format[index + 1] != 'm')
          {
            index ++;
            break;
          };
          stm.tm_min =
            ((str[index] - 0x30) * 10) +
            (str[index + 1] - 0x30);
          index = index + 2;
          break;
        };
      case 'h':
        {
          if (format[index + 1] != 'h')
          {
            index ++;
            break;
          };
          stm.tm_hour =
            ((str[index] - 0x30) * 10) +
            (str[index + 1] - 0x30);
          index = index + 2;
          break;
        };
      case 'D':
        {
          if (format[index + 1] != 'D')
          {
            index ++;
            break;
          };
          stm.tm_mday =
            ((str[index] - 0x30) * 10) +
            (str[index + 1] - 0x30);
          index = index + 2;
          break;
        };
      case 'M':
        {
          if (format[index + 1 ] != 'M')
          {
            index ++;
            break;
          };
          stm.tm_mon =
            ((str[index] - 0x30) * 10) +
            (str[index + 1] - 0x30) - 1;

          index = index + 2;
          break;
        };
      case 'Y':
        {
          ptr = &format[index];

          if (memcmp(ptr ,"YYYY", 4) == 0)
          {
            stm.tm_year =
              ((str[index]     - 0x30) * 1000) +
              ((str[index + 1] - 0x30) * 100) +
              ((str[index + 2] - 0x30) * 10) +
              ((str[index + 3] - 0x30)) - 1900;

            index = index + 4;
            break;
          }
          if (format[index + 1 ] != 'Y')
          {
            index ++;
            break;
          };
          stm.tm_year =
            ((str[index] - 0x30) * 10) +
            (str[index + 1] - 0x30);

          index = index + 2;
          break;
        };
      default :
        {
          index ++;
        };
    }
  }

  return mktime(&stm);
}

