/*
  Copyright (C) 2001 PENTA SECURITY SYSTEMS, INC.
  All rights reserved

  THIS IS UNPUBLISHED PROPRIETARY
  SOURCE CODE OF PENTA SECURITY SYSTEMS, INC.
  The copyright notice above does not evidence any 
	actual or intended publication of such source code.

  Filename : GetProfile.h
*/

#ifndef _GET_PROFILE_H
#define _GET_PROFILE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/**
 * 설정 파일로부터 지정된 section의 지정된 key에 해당하는 값을 읽어온다.
 * @param *file (In)  설정파일 명
 * @param *sec  (In)  Section 명
 * @param *key  (In)  Key 이름
 * @param *val  (Out) 읽어온 값이 저장될 버퍼
 * @param  size (Out) 버퍼의 크기
 * @return 
 *   설정파일로부터 읽어들인 값의 길이, 실패한 경우는 -1
 */
size_t GetProfile(const char *filePath, const char *sec, 
                  const char *key, char *val, size_t size);

int SetProfile(const char *filePath, const char *sec, const char *key, 
               const char *val);

int DeleteProfile(const char *filePath, const char *sec, const char *key);

/**
 * Get Section Names From Configure file
 * @param *filePath	(In)	Configure file name
 * @param **sec			(Out)	Section names
 * @param num				(In)	Section names max num
 * @return
 * 	Number of Section names, if fail return -1
 */
size_t GetSections(const char *filePath, char** secs, const size_t num);

/**
 * Get Key Names from Configure file in given section
 * @param *filePath	(In)	Configure file name
 * @param *section	(In)	Section name
 * @param **keys		(Out)	Key names
 * @param num				(In)	Key names max num
 * @return
 * 	Number of Key names, if fails return -1
 */
size_t GetKeys(const char *filePath, const char* section, char** keys, const size_t num);

#ifdef __cplusplus
}
#endif

#endif /* _GET_PROFILE_H */
