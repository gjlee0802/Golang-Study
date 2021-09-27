#include "Trace.h"

int main()
{
  TRACE("Hello %d, %s\n", 1, "test");
  TRACE("%s, %s", PRETTY_TRACE_STRING, "got it\n");
  return 0;
}
