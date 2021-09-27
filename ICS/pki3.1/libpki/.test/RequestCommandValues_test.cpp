#include <iostream>

#include "RequestCommandValues.hpp"

using namespace Issac;
using namespace std;

int main(void)
{
  RequestCommandValues v;
  v.setRequestID("TEST");
  v.setInput("-al", "hahaha");

  string args, input;
  v.getInput(args, input);
  cout << v.getRequestID() << endl;
  cout << args << "\t" << input << endl;
  cout << v.getBuffer() << endl;

  return 0;
}
