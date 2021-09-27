/**
 * @file      Echo.c
 *
 * @desc      Echo function
 * @author    Cho, Hyoen Rae(velvetfish@hotmail.com)
 * @since     2003.02.20
 */

#include "Echo.h"

#ifdef WIN32
  #include <conio.h>
  #include <windows.h>
#else
  #include <strings.h>
  #include <termios.h>
  #include <sys/ioctl.h>
#endif

void EchoOff()
{
#ifndef WIN32
  struct termios io;
#ifdef _Darwin
  ioctl(0, TIOCGETA, &io);
#else
  ioctl(0, TIOCGETD, &io);
#endif
  io.c_lflag &=  ~ECHO;
#ifdef _Darwin
  ioctl(0, TIOCSETA, &io);
#else
  ioctl(0, TIOCSETD, &io);
#endif
#else
  HANDLE hin;
  DWORD mode;
  hin = GetStdHandle(STD_INPUT_HANDLE);
  GetConsoleMode(hin, &mode);
  mode = mode & ~(ENABLE_ECHO_INPUT);
  SetConsoleMode(hin, mode);
#endif
}

void EchoOn()
{
#ifndef WIN32
  struct termios io;
#ifdef _Darwin
  ioctl(0, TIOCGETA, &io);
#else
  ioctl(0, TIOCGETD, &io);
#endif
  io.c_lflag |=  ECHO;
#ifdef _Darwin
  ioctl(0, TIOCSETA, &io);
#else
  ioctl(0, TIOCSETD, &io);
#endif
#else
  HANDLE hin;
  DWORD mode;
  hin = GetStdHandle(STD_INPUT_HANDLE);
  GetConsoleMode(hin, &mode);
  mode |= ENABLE_ECHO_INPUT;
  SetConsoleMode(hin, mode);
#endif
}
