#include <string.h>
#include <stdlib.h>
#ifdef WIN32
#include <windows.h>
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")
#else
#include <unistd.h>
#include <errno.h> 
#endif

#include "CommandLineArgs.h"
#include "separator.h"
#include "Trace.h"

int GetPathAndModuleNameFromArgs(const char *argv0, char *path, char *name)
{
  char pwdmod[256], pwd[256], *ptr;
  char filepath[256], *ptr2;
  int i, j;
  char prevchar, curchar;

  /* Path 설정 */
	/* soft link에 의한 실행시 실경로를 가져오면 안되기에... */
	char *pwdLink = getenv("PWD");
	if(pwdLink != NULL)
	{
		strcpy(pwd, pwdLink);
		//free(pwdLink);
	} else getcwd(pwd, 256);

  if(strchr(argv0, FILE_SEPARATOR)) 
  {
    if(argv0[0] == FILE_SEPARATOR ||
      (strlen(argv0) > 1 && argv0[1] == ':'))
    {
      // 절대 경로로 실행된 경우
      strcpy(pwd, argv0);
    }
    else 
    {
      // 상대 경로로 실행된 경우
      strcat(pwd, FILE_SEPARATOR_STR);
      strcat(pwd, argv0);
    }

MAKE_PATH:

    // 경로에 /가 반복되는 것 보정
    j = -1;
    prevchar = 0;
    for (i = 0; *(pwd + i) != 0; ++i)
    {
      curchar = *(pwd + i);
      if (prevchar == FILE_SEPARATOR && curchar == FILE_SEPARATOR)
        continue;

      pwdmod[++j] = curchar;
      prevchar = curchar;
    }
    pwdmod[++j] = 0;
    strcpy(pwd, pwdmod);

    while ((ptr = strstr(pwd, ".." FILE_SEPARATOR_STR))) 
    {
      for (ptr2 = ptr-2; *ptr2 != FILE_SEPARATOR; ptr2--);
      if (ptr2 < pwd) ptr2 = pwd;
      memmove(ptr2, ptr+2, strlen(ptr+2)+1);
    }

    while ((ptr = strstr(pwd, "." FILE_SEPARATOR_STR))) 
    {
      memmove(ptr, ptr+2, strlen(ptr+2)+1);
    }
  }
  else
  {
    // 실행 파일 이름만 입력하여 실행한 경우 : PATH에서 찾음
    char *PATH = malloc(strlen(getenv("PATH")) + 10);
    char *tmp;
    PATH[0] = 0;
#ifdef __CYGWIN__
    strcat(PATH, "." FILE_SEPARATOR_STR PATH_SEPARATOR_STR); 
    // window에서는 무조건 앞에서 찾는다.
#else
#ifdef _WIN32
    strcat(PATH, "." FILE_SEPARATOR_STR PATH_SEPARATOR_STR); 
    // window에서는 무조건 앞에서 찾는다.
#endif
#endif
    strcat(PATH, getenv("PATH"));
    tmp = PATH;
    ptr = strtok(tmp, PATH_SEPARATOR_STR);

    do 
    {
      if (ptr[0] != FILE_SEPARATOR) 
      {
        strcpy(filepath, pwd);
        strcat(filepath, FILE_SEPARATOR_STR);
        strcat(filepath, ptr);
      } 
      else
        strcpy(filepath, ptr);

      if (filepath[strlen(filepath)-1] != FILE_SEPARATOR)
        strcat(filepath, FILE_SEPARATOR_STR);

      strcat(filepath, argv0);

      if (!access(filepath, X_OK)) 
      {
        strcpy(pwd, filepath);
        free(PATH);
        goto MAKE_PATH;
      }

    } while ((ptr = strtok(NULL, PATH_SEPARATOR_STR)));

    free(PATH);
    return -1;
  }

  ptr = strrchr(pwd, FILE_SEPARATOR);

  strcpy(name, ptr + 1); /* 실행 파일의 이름을 기록 */
  *(++ptr) = '\0';
  strcpy(path, pwd); /* 실행 파일의 경로를 기록 */

  return 0;
}

int GetOptionValueFromArgs(int argc, char * const *argv, 
  const char *longOpt, const char *shortOpt, char *val)
{
  int i = 0;
  if (val != NULL)
    val[0] = 0;

  for (i = 1; i < argc; i++)
  {
    // 한 칸 띄어쓴 롱 옵션
    if (longOpt && strlen(longOpt))
    {
      char opt[256] = { '-', '-', 0 };
      strcat(opt, longOpt);
      if (strcmp(opt, argv[i]) == 0)
      {
        if (argc > (i + 1))
          if (val)
            strcpy(val, argv[i + 1]);

        return 0; // 다음 아규먼트가 없다해도 옵션은 주어졌으므로 0을 리턴
      }
    }
    // =로 할당한 롱 옵션
    if (longOpt && strlen(longOpt))
    {
      char opt[256] = { '-', '-', 0 };
      strcat(opt, longOpt);
      strcat(opt, "=");
      if (strstr(argv[i], opt) == argv[i])
      {
        if (val)
          strcpy(val, argv[i] + strlen(opt));
        return 0;
      }
    }
    // 한 칸 띄어쓴 쇼트 옵션
    if (shortOpt && strlen(shortOpt))
    {
      char opt[256] = { '-', 0 };
      strcat(opt, shortOpt);
      if (strcmp(opt, argv[i]) == 0 && argc > (i + 1))
      {
        if (val)
          strcpy(val, argv[i + 1]);
        return 0;
      }
    }
    // 붙여 쓴 쑈트 옵션
    if (shortOpt && strlen(shortOpt))
    {
      char opt[256] = { '-', 0 };
      strcat(opt, shortOpt);
      if (strstr(argv[i], opt) == argv[i])
      {
        if (val)
          strcpy(val, argv[i] + strlen(opt));
        return 0;
      }
    }
  }
  return -1;
}

