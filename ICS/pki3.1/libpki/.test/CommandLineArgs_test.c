#include <stdio.h>

#include "CommandLineArgs.h"

int main(int argc, char * const *argv)
{
  char val[256] = { 0 };
  int i;

  i = GetOptionValueFromArgs(argc, argv, "test", NULL, val);
  printf("by long option, %d, %s\n", i, val);
  i = GetOptionValueFromArgs(argc, argv, NULL, "t", val);
  printf("by short option, %d, %s\n", i, val);
  i = GetOptionValueFromArgs(argc, argv, "test", "t", val);
  printf("by both option, %d, %s\n", i, val);

  return 0;
}

