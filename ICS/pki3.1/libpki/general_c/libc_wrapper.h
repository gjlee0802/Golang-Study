#ifndef LOCK_H_
#define LOCK_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h> /* required for some of our prototypes */
#include <stdio.h>   /* for convenience */
#include <stdlib.h>    /* for convenience */
#include <string.h>    /* for convenience */
#include <unistd.h>    /* for convenience */
#include <fcntl.h>

// return -1 if fail
int lock_reg(int fd, int cmd, int type, off_t offset, int whence, off_t len);
// return 0 if fail
pid_t lock_test(int fd, int type, off_t offset, int whence, off_t len);

#define read_lock(fd, offset, whence, len) \
        lock_reg(fd, F_SETLK, F_RDLCK, offset, whence, len)
#define readw_lock(fd, offset, whence, len) \
        lock_reg(fd, F_SETLKW, F_RDLCK, offset, whence, len)
#define write_lock(fd, offset, whence, len) \
        lock_reg(fd, F_SETLK, F_WRLCK, offset, whence, len)
#define writew_lock(fd, offset, whence, len) \
        lock_reg(fd, F_SETLKW, F_WRLCK, offset, whence, len)
#define un_lock(fd, offset, whence, len) \
        lock_reg(fd, F_SETLK, F_UNLCK, offset, whence, len)

#define is_readlock(fd, offset, whence, len) \
        lock_test(fd, F_RDLCK, offset, whence, len)
#define is_writelock(fd, offset, whence, len) \
        lock_test(fd, F_WRLCK, offset, whence, len)


typedef	void	sigfunc(int);	/* for signal handlers */

sigfunc *Signal(int signo, sigfunc *func);

#ifdef __cplusplus
}
#endif

#endif

