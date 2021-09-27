#include <stdio.h>
#include <iostream>
#include "lock.h"

using namespace std;

int main()
{
  int fd = open("/tmp/mdpid", O_RDWR | O_CREAT | O_TRUNC, 0644);

  if (fd == -1)
  {
    printf("open file fail\n");
    return -1;
  }
  cout << "is_writelock returned: " << is_writelock(fd, 0, 0, 0) << endl;
  cout << "write_lock returned: " << write_lock(fd, 0, 0, 0) << endl;

  cout << "i'm sleeping..." << endl;

  sleep(10);
  close(fd);
}

