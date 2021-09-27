#include <signal.h>
#include <errno.h>


#include "libc_wrapper.h"

int lock_reg(int fd, int cmd, int type, off_t offset, int whence, off_t len)
{
  int ret = 0 ;
	struct flock  lock;

  lock.l_type = type;   /* F_RDLCK, F_WRLCK, F_UNLCK */
  lock.l_start = offset;  /* byte offset, relative to l_whence */
  lock.l_whence = whence; /* SEEK_SET, SEEK_CUR, SEEK_END */
  lock.l_len = len;   /* #bytes (0 means to EOF) */

	//Many Process writes One file .  
  while( (ret = fcntl(fd, cmd, &lock)) == -1 )
  {
	  if(errno != EAGAIN)  break;
	  
	  usleep(10);
  } 
    
  return( ret );
}

pid_t lock_test(int fd, int type, off_t offset, int whence, off_t len)
{
  struct flock  lock;

  lock.l_type = type;   /* F_RDLCK or F_WRLCK */
  lock.l_start = offset;  /* byte offset, relative to l_whence */
  lock.l_whence = whence; /* SEEK_SET, SEEK_CUR, SEEK_END */
  lock.l_len = len;   /* #bytes (0 means to EOF) */

  if (fcntl(fd, F_GETLK, &lock) < 0)
    return 0;

  if (lock.l_type == F_UNLCK)
    return 0;    /* false, region is not locked by another proc */

  return(lock.l_pid); /* true, return pid of lock owner */
}

/* Reliable version of signal(), using POSIX sigaction().  */

sigfunc *
Signal(int signo, sigfunc *func)
{
	struct sigaction	act, oact;

	act.sa_handler = func;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if (signo == SIGALRM) {
#ifdef	SA_INTERRUPT
		act.sa_flags |= SA_INTERRUPT;	/* SunOS */
#endif
	} else {
#ifdef	SA_RESTART
		act.sa_flags |= SA_RESTART;		/* SVR4, 44BSD */
#endif
	}
	if (sigaction(signo, &act, &oact) < 0)
		return(SIG_ERR);
	return(oact.sa_handler);
}

