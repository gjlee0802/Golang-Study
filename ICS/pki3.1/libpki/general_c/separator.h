/*
  Copyright (C) 2001 PENTA SECURITY SYSTEMS, INC.
  All rights reserved

  THIS IS UNPUBLISHED PROPRIETARY
  SOURCE CODE OF PENTA SECURITY SYSTEMS, INC.
  The copyright notice above does not evidence any 
	actual or intended publication of such source code.

  Filename : separator.h
*/

#ifndef _SEPARATOR_H
#define _SEPARATOR_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
  #define FILE_SEPARATOR       '\\'
  #define FILE_SEPARATOR_STR   "\\"
  #define PATH_SEPARATOR       ';'
  #define PATH_SEPARATOR_STR   ";"
  #define X_OK                 6
#else 
  #define FILE_SEPARATOR       '/'
  #define FILE_SEPARATOR_STR   "/"
  #define PATH_SEPARATOR       ':'
  #define PATH_SEPARATOR_STR   ":"
#endif

#ifdef __cplusplus
}
#endif

#endif
