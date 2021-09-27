/*
  Copyright (C) 2001 PENTA SECURITY SYSTEMS, INC.
  All rights reserved

  THIS IS UNPUBLISHED PROPRIETARY
  SOURCE CODE OF PENTA SECURITY SYSTEMS, INC.
  The copyright notice above does not evidence any 
	actual or intended publication of such source code.

  Filename : GetProfileEx.hpp
*/

#ifndef _GET_PROFILE_EX_HPP
#define _GET_PROFILE_EX_HPP

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
void GetProfileEx(const std::string &filePath, const std::string &sec, 
    const std::string &key, std::string &val, const std::string &defVal = "");

void SetProfileEx(const std::string &filePath, const std::string &sec, 
    const std::string &key, const std::string &val);

void DeleteProfileEx(const std::string &filePath, const std::string &sec, 
    const std::string &key);

#ifdef __cplusplus
}
#endif

#endif /* _GET_PROFILE_H */
