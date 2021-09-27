
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "GetProfile.h"
#include "er_define.h"

#define MAX_BUFFER_SIZE 8192

#if defined(WIN32) || defined(__CYGWIN__)
	#define _LF 2
#else
	#define _LF 1
#endif

#define MIN(x,y) ((x) > (y) ? (y) : (x))
#define MAX_SEC_LEN 300

size_t GetProfile(const char *filePath, const char *section, 
                  const char *key, char *value, size_t size)
{
  FILE *fp;
  char line[MAX_BUFFER_SIZE], *token, sec[MAX_SEC_LEN];
  static char *delim = "\n\r=";
  static char *delim2 = "\n\r";

  value[0] = 0;

  memset(sec, 0, MAX_SEC_LEN);
  sec[0] = '[';
  memcpy(sec + 1, section, MIN(strlen(section), MAX_SEC_LEN - 2));
  strcat(sec, "]");

  if ((fp = fopen(filePath, "r"))) 
	{
    while (fgets(line, MAX_BUFFER_SIZE, fp)) 
		{
      token = strtok(line, delim);
      if (token && strcmp(sec, token) == 0) // SEC
			{
        while (fgets(line, MAX_BUFFER_SIZE, fp)) 
				{
          token = strtok(line, delim);
          if (token && strcmp(key, token) == 0) // KEY
					{
            token = strtok(NULL, delim2);
            if (token) // VAL
						{
              if (size <= strlen(token))
                token[size-1] = 0;
              strcpy(value, token);
            }

						fflush(fp);
						fclose(fp);
            return strlen(value);
          }
          else if (token && token[0] == '[') 
					{
						fclose(fp);
            return 0;
          }
        }
				fclose(fp);
        return 0;
      }
    }
	  fclose(fp);
    return 0;
  }
	strcpy(value, "");
  return 0;
}

int SetProfile(const char *filePath, const char *section, const char *key, 
               const char *value)
{
  FILE *fp;
  char *content, line[MAX_BUFFER_SIZE], *token, sec[MAX_SEC_LEN];
  static char *delim = "\n\r=";
  long filepos, filelen, linelen;
  int nolfprev, lfcur;
  size_t seclen, keylen, vallen;

  memset(sec, 0, MAX_SEC_LEN);
  sec[0] = '[';
  memcpy(sec + 1, section, MIN(strlen(section), MAX_SEC_LEN - 2));
  strcat(sec, "]");

  seclen = strlen(sec);
  keylen = strlen(key);
  vallen = strlen(value);

  if ((fp = fopen(filePath, "r+b")) || (fp = fopen(filePath, "w+"))) 
	{
    fseek(fp, 0, SEEK_END);
    filelen = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    lfcur = 0;
    while (fgets(line, MAX_BUFFER_SIZE, fp)) 
		{
      lfcur = ('\n' == line[strlen(line)-1]);
      token = strtok(line, delim);
      if (token && strcmp(sec, token) == 0) 
			{
        while (fgets(line, MAX_BUFFER_SIZE, fp)) 
				{
          linelen = strlen(line);
          nolfprev = !lfcur;
          lfcur = ('\n' == line[linelen-1]);
          token = strtok(line, delim);
          if (token && strcmp(key, token) == 0) 
					{
            if ((content = malloc(filelen-linelen+keylen+vallen+2+(nolfprev+lfcur)*_LF))) 
						{
              if (nolfprev) 
							{
#if defined(WIN32) || defined(__CYGWIN__)
                content[0] = '\r';
#endif
                content[_LF - 1] = '\n';
              }

              filepos = ftell(fp);
              strcpy(content + (nolfprev * _LF + (filepos - linelen)), key);
              content[filepos - linelen + keylen + nolfprev * _LF] = '=';
              strcpy(content + (filepos - linelen + keylen + nolfprev * _LF + 1), value);
              if (lfcur) 
							{
#if defined(WIN32) || defined(__CYGWIN__)
                content[filepos - linelen + keylen + nolfprev * _LF + 1 + vallen] = '\r';
#endif
                content[filepos - linelen + keylen + (nolfprev + 1) * _LF + vallen] = '\n';
              }

              fread(content + (filepos - linelen + keylen + 1 + vallen + _LF * (nolfprev + lfcur)), sizeof(char), filelen - filepos, fp);
              fseek(fp, 0, SEEK_SET);
              fread(content, sizeof(char), filepos - linelen, fp);
              fclose(fp);
              fp = fopen(filePath, "wb");
              fwrite(content, sizeof(char), filelen - linelen + keylen + 
                      vallen + 1 + (nolfprev + lfcur) * _LF, fp);
							fflush(fp);
              fclose(fp);
              free(content);
              return 0;
            }
            else 
						{
              fclose(fp);
              return -1;
            }
          }
          else if (token && token[0] == '[') 
					{
            fseek(fp, -linelen, SEEK_CUR);
            filepos = ftell(fp);
            if ((content = malloc(filelen - filepos + keylen + vallen + 1 + _LF))) 
						{
              strcpy(content, key);
              content[keylen] = '=';
              strcpy(content + (keylen + 1), value);
#if defined(WIN32) || defined(__CYGWIN__)
              content[keylen + 1 + vallen] = '\r';
#endif
              content[keylen + _LF + vallen] = '\n';
              fread(content + (keylen + 1 + _LF + vallen), sizeof(char), filelen - filepos, fp);
              fseek(fp, filepos, SEEK_SET);
              fwrite(content, sizeof(char), filelen - filepos + keylen + vallen + 1 + _LF, fp);
							fflush(fp);
              fclose(fp);
              free(content);
              return 0;
            }
            else 
						{
              fclose(fp);
              return -1;
            }
          }
        }

        nolfprev = !lfcur;
        if ((content = malloc(keylen + vallen + 1 + (nolfprev + 1) * _LF))) 
				{
          if (nolfprev) 
					{
#if defined(WIN32) || defined(__CYGWIN__)
            content[0] = '\r';
#endif
            content[_LF - 1] = '\n';
          }
          strcpy(content + nolfprev * _LF, key);
          content[keylen + nolfprev * _LF] = '=';
          strcpy(content + (keylen + nolfprev * _LF + 1), value);
#if defined(WIN32) || defined(__CYGWIN__)
          content[keylen + vallen + nolfprev * _LF + 1] = '\r';
#endif
          content[keylen + vallen + (nolfprev + 1) * _LF] = '\n';

          fwrite(content, sizeof(char), keylen + vallen + 1 + (nolfprev + 1) * _LF, fp);
					fflush(fp);
          fclose(fp);
          free(content);
          return 0;
        }
        else 
				{	
          fclose(fp);
          return -1;
        }
      }
    }

    nolfprev = !lfcur;
    if ((content = malloc(seclen + keylen + vallen + 1 + (nolfprev + 2) * _LF))) 
		{
      if (nolfprev) 
			{
#if defined(WIN32) || defined(__CYGWIN__)
        content[0] = '\r';                                                
#endif                                                                            
        content[_LF - 1] = '\n';                                          
      }                                                                     
      strcpy(content + nolfprev * _LF, sec);                                
#if defined(WIN32) || defined(__CYGWIN__)
      content[seclen + nolfprev * _LF] = '\r';                              
#endif                                                                            
      content[seclen + (nolfprev + 1) * _LF - 1] = '\n';                    

      strcpy(content + (seclen + (nolfprev + 1) * _LF), key);               
      content[seclen + keylen + (nolfprev + 1) * _LF] = '=';                
      strcpy(content + (seclen + keylen + (nolfprev + 1) * _LF + 1), value);
#if defined(WIN32) || defined(__CYGWIN__)
      content[seclen + keylen + (nolfprev + 1) * _LF + 1 + vallen] = '\r';
#endif
      content[seclen + keylen + (nolfprev + 2) * _LF + vallen] = '\n';

      fwrite(content, sizeof(char), seclen + keylen + vallen + 1 + (nolfprev + 2) * _LF, fp);
			fflush(fp);
      fclose(fp);
      free(content);
      return 0;
    }
    else 
		{
      fclose(fp);
      return -1;
    }
  }
  ER_RET_VAL(-1);
}

int DeleteProfile(
				const char *filePath, 
				const char *section, 
				const char *key)
{
  FILE *fp;
  char *content, line[MAX_BUFFER_SIZE], *token, sec[MAX_SEC_LEN];
  static char *delim = "\n\r=";
  long filepos, filelen, linelen;

  memset(sec, 0, MAX_SEC_LEN);
  sec[0] = '[';
  memcpy(sec + 1, section, MIN(strlen(section), MAX_SEC_LEN - 2));
  strcat(sec, "]");

  if ((fp = fopen(filePath, "r+b"))) 
	{
    fseek(fp, 0, SEEK_END);
    filelen = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    while (fgets(line, MAX_BUFFER_SIZE, fp)) 
		{
      token = strtok(line, delim);
      if (token && strcmp(sec, token) == 0) 
			{
        while (fgets(line, MAX_BUFFER_SIZE, fp)) 
				{
          linelen = strlen(line);
          token = strtok(line, delim);
          if (token && strcmp(key, token) == 0) 
					{
            filepos = ftell(fp);
            if ((content = malloc(filelen - linelen))) 
						{
              fread(content + (filepos - linelen), sizeof(char), filelen - filepos, fp);
              fseek(fp, 0, SEEK_SET);
              fread(content, sizeof(char), filepos - linelen, fp);
              fclose(fp);
              fp = fopen(filePath, "wb");
              fwrite(content, sizeof(char), filelen - linelen, fp);
              fflush(fp);
              fclose(fp);
              free(content);
              return 0;
            }
            else 
						{
              fclose(fp);
              return -1;
            }
          }
          else if (token && token[0] == '[') 
					{
            fclose(fp);
            return 0;
          }
        }
      }
    }
  }
  return 0;
}

size_t GetSections(const char *filePath, char** secs, const size_t num)
{
	int i = 0;
  FILE *fp;
  char line[MAX_BUFFER_SIZE], *token;
  static char *delim = "\n\r=";
  static char *delim2 = "\n\r";

  if ((fp = fopen(filePath, "r"))) 
	{
    while (fgets(line, MAX_BUFFER_SIZE, fp) && (size_t)i < num) 
		{
      token = strtok(line, delim);
      if (token && '[' == token[0] && ']' == token[strlen(token)-1]) // SEC
			{
				if( strlen(token) < MAX_SEC_LEN ){
						strcpy(secs[i], token+1);
						secs[i][strlen(token)-2] = '\0';
						i++;
				}
      }
    }
	  fclose(fp);
    return (size_t)i;
  }
  return 0;
}


size_t GetKeys(const char *filePath, const char* section, char** keys, const size_t num)
{
	int i = 0, len = 0;
  FILE *fp;
  char line[MAX_BUFFER_SIZE], *token, sec[MAX_SEC_LEN];
  static char *delim = "\n\r=";
  static char *delim2 = "\n\r";

  memset(sec, 0, MAX_SEC_LEN);
  sec[0] = '[';
  memcpy(sec + 1, section, MIN(strlen(section), MAX_SEC_LEN - 2));
  strcat(sec, "]");

  if ((fp = fopen(filePath, "r"))) 
	{
    while (fgets(line, MAX_BUFFER_SIZE, fp)) 
		{
      token = strtok(line, delim);
      if (token && strcmp(sec, token) == 0) // SEC
			{
        while (fgets(line, MAX_BUFFER_SIZE, fp)) 
				{
					if( (size_t)i < num ){
          	token = strtok(line, delim);
          	if (token && token[0] == '[') break; // Another Sec
						if( token && MAX_BUFFER_SIZE	> strlen(token) ){
						  len = strlen(token);
              strncpy(keys[i], token, len);
              keys[i][len]='\0';
							i++;
            }
					}
        }
				fclose(fp);
				return (size_t)i;
      }
    }
	  fclose(fp);
    return 0;
  }
  return -1;
}



