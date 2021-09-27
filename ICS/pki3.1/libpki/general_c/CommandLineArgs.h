/*
  Copyright (C) 2001 PENTA SECURITY SYSTEMS, INC.
  All rights reserved

  THIS IS UNPUBLISHED PROPRIETARY
  SOURCE CODE OF PENTA SECURITY SYSTEMS, INC.
  The copyright notice above does not evidence any 
	actual or intended publication of such source code.

  Filename : CommandLineArgs.h
*/

#ifndef _COMMAND_LINE_ARGS_H
#define _COMMAND_LINE_ARGS_H

#ifdef __cplusplus
extern "C" {
#endif

int GetPathAndModuleNameFromArgs(const char *argv0, char *path, char *name);

// 아래 함수의 문제는, 실제로는 가령 -jd 의 경우 j가 목적어를 가지는 옵션이면
// d는 옵션이 아니고, 목적어를 가지지 않는 옵션이면 d는 옵션인데
// 이를 판단할 수 없다는 점이다. 즉 위와 같은 옵션이 주어지면 아래의 함수는
// d를 옵션이 아닌 목적어로 판단해 버린다. 
//
// 위의 경우를 제외하고, 잘 작동하며 작동 방식은 쇼트 옵션 또는 롱 옵션을
// 주고 이에 대한 목적어를 반환한다. 물론 옵션이 없으면 -1을 리턴한다.
// 만약 목적어가 아닌 옵션이 있는지 여부만 알고 싶다면 val에 NULL을
// 넣고 호출해도 된다.
int GetOptionValueFromArgs(int argc, char * const *argv, const char *longOpt, 
                           const char *shortOpt, char *val);

#ifdef __cplusplus
}
#endif

#endif
