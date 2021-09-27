/**
 * @file     KeyPress.h
 *
 * @desc     KeyPress관련 함수
 * @author   조현래 (hrcho@pentasecurity.com)
 * @since    2001.10.29
 *
 */

#include <stdlib.h>
#include <stdio.h>

#include <termios.h>
#include <string.h>

static struct termios storedSettings;

void SetKeyPress(void)
{
    struct termios newSettings;

    tcgetattr(0, &storedSettings);

    newSettings = storedSettings;

    /* Disable canonical mode, and set buffer size to 1 byte */
    newSettings.c_lflag &= (~ICANON);
    newSettings.c_cc[VTIME] = 0;
    newSettings.c_cc[VMIN] = 1;

    tcsetattr(0, TCSANOW, &newSettings);
    return;
}

void ResetKeyPress(void)
{
    tcsetattr(0, TCSANOW, &storedSettings);
    return;
}

