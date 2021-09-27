/* 
   Copyright (C) 2000 PENTA SECURITY SYSTEMS, INC.
   All rights reserved

   THIS IS UNPUBLISHED PROPRIETARY 
   SOURCE CODE OF PENTA SECURITY SYSTEMS, INC.
   The copyright notice above does not evidence any actual or 
   intended publication of such source code.

   Filename : KeyPress.h
*/

#ifndef _KEY_PRESS_H_
#define _KEY_PRESS_H_

#ifdef __cplusplus
extern "C" {
#endif

/* WIN32로 포팅되어 있지 않다. UNIX/LINUX 에서만 돌아간다. */

// non-canonical mode로 한자씩 key input을 받는다.
void SetKeyPress();

// canonical mode로 복귀. line단위로 key input을 받는다.
void ResetKeyPress();

#ifdef __cplusplus
}
#endif

#endif /* _KEY_PRESS_H_ */

